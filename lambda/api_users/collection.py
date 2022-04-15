"""Request Handler for /users API Route

This is implemented as a Lambda Proxy integration.  The function is
responsible for validating the input, and sending a properly-formatted
response.  (Failure to do so will be a 5xx error for the client.)

https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
https://docs.aws.amazon.com/apigateway/latest/developerguide/handle-errors-in-lambda-integration.html

This script requires some external packages for various operations.  Since the
vanilla AWS runtime has a limited set of libraries, we bundle our third party
packages into the videon_shared Lambda layer (along with our own shared
functions), which is automatically extracted under /opt in the include path.
See README.md for more info about managing external dependencies.
"""

import boto3
import botocore

import logging
import requests
import json
import re
import videon_shared as videon

from typing import Union

from os import environ
from distutils.util import strtobool

# Enable X-Ray Tracing
from aws_xray_sdk.core import patch_all

patch_all()

_cognito = boto3.client("cognito-idp")
_cognito_user_pool_id = environ.get("COGNITO_USER_POOL_ID")
_cognito_client_id = environ.get("COGNITO_USER_POOL_CLIENT_ID")

RESTAPI_URL_PATH = environ.get("RESTAPI_URL_PATH")

# Email regex used for checking create_user
_REGEX_EMAIL = r"^[\w_+&*-]+(?:\.[\w_+&*-]+)*@(?:[\w-]+\.)+[a-zA-Z]{2,7}$"
_REGEX_PHONE_NUMBER = r"^\+?[1-9]\d{1,14}$"

# List of user attributes that we use.  Only a subset of these are searchable.
# Cognito uses slightly different names than we do.  Note that Cognito has a
# handful of other fields, which we do not use and leave blank.
_USER_ATTRIBUTES_SEARCHABLE = ("user_guid", "name", "email", "phone_number",
                               "enabled", "status")
_USER_ATTRIBUTES_TO_COGNITO = {
    "user_guid": "sub",
    "name": "name",
    "email": "email",
    "phone_number": "phone_number",
    "enabled": "status",
    "status": "cognito:user_status",
    "locale": "locale",
    "zoneinfo": "zoneinfo"
}

COGNITO_USER_MANAGEMENT_GROUP_NAME = environ.get(
    "COGNITO_USER_MANAGEMENT_GROUP_NAME")

_secretsmanager = boto3.client("secretsmanager")
VIDEON_INTERNAL_AUTH_SECRET = _secretsmanager.get_secret_value(
    SecretId=environ["VIDEON_INTERNAL_AUTH_ARN"])["SecretString"]
VIDEON_INTERNAL_HEADERS = {
    "Authorization": f"VIDEON_INTERNAL_AUTH {VIDEON_INTERNAL_AUTH_SECRET}"
}

logger = logging.getLogger()


def lambda_handler(event, context):  # pylint: disable=unused-argument

    videon.setup_logging(logging.INFO, event)

    # If this fails the API gateway is misconfigured
    supported_methods = ("GET", "POST", "OPTIONS")
    assert event["httpMethod"] in supported_methods

    if event["httpMethod"] == "GET":
        # The API gateway validates the parameters, so this should only fail
        # if the API gateway is misconfigured
        params = event["queryStringParameters"]
        assert "search_attribute" in params
        assert "search_value" in params

        user_guid = videon.get_authorizer_guid(event)
        pagination_encryption_key = videon.pagination_encryption_key(
            context.function_name, user_guid, videon.is_internal_auth(event))

        if not params["search_attribute"] in _USER_ATTRIBUTES_SEARCHABLE:
            return videon.response_json(
                400, {
                    "message":
                        "Invalid value '{%s}' in parameter search_attribute" %
                        str(params["search_attribute"])
                }, event)

        # Look up the Cognito attribute name from our user-friendly name
        search_attribute_name_cognito = _USER_ATTRIBUTES_TO_COGNITO[
            params["search_attribute"]]
        search_value = params["search_value"]
        pagination_token = params.get("pagination_token")
        pagination_size = params.get("pagination_size")

        try:
            pagination_size = videon.validate_pagination_size(pagination_size)
        except (TypeError, ValueError) as err:
            response_json = {"message": "Invalid pagination size. " + str(err)}
            response_code = 400
            return videon.response_json(response_code, response_json, event)

        try:
            starts_with = bool(strtobool(params.get("starts_with", "false")))
        except ValueError as err:
            return videon.response_json(
                400, {
                    "message":
                        "Invalid value '{}' in parameter starts_with".format(
                            params.get("starts_with", "undefined"))
                }, event)

        # Check if searching for enabled users, in which case convert to
        # consumable values
        if params["search_attribute"] == "enabled":
            search_value = "Enabled" if search_value == "true" else "Disabled"

        try:
            pagination_token = videon.pagination_decrypt(
                pagination_token, pagination_encryption_key)

            authorizer_user_groups = videon.get_user_groups(event)
            is_user_admin = bool(
                COGNITO_USER_MANAGEMENT_GROUP_NAME in authorizer_user_groups)
            admin_view = is_user_admin or videon.is_internal_auth(event)

            response = find_users(user_guid, search_attribute_name_cognito,
                                  search_value, starts_with, pagination_token,
                                  pagination_size, admin_view)

            response["pagination_token"] = videon.pagination_encrypt(
                response["pagination_token"], pagination_encryption_key)
        except videon.PaginationTokenError:
            return videon.response_json(400,
                                        {"message": "Invalid pagination token"},
                                        event)

        return videon.response_json(200, response, event)

    elif event["httpMethod"] == "POST":
        # Make sure the request body is valid JSON before processing.
        # If it was, the API Gateway should have already validated the
        # parameters.
        try:
            body = videon.convert_request_body(event["body"])
        except videon.RequestBodyError as err:
            return videon.response_json(400, {"message": str(err)}, event)

        # The API gateway validates the parameters, so this should only fail
        # if the API gateway is misconfigured
        assert "name" in body
        assert "email" in body
        assert "password" in body
        assert "locale" in body
        assert "zoneinfo" in body

        # Validate name contains at least once space
        if not body["name"].count(" ") >= 1:
            return videon.response_json(
                400, {"message": "Name must contain at least one space"}, event)

        # Validate email looks valid (library or check for '@')
        if not re.match(_REGEX_EMAIL, body["email"]):
            return videon.response_json(400, {"message": "Email invalid"},
                                        event)

        # Validate phone number, locale, and zoneinfo using OpenID spec
        if "phone_number" in body:
            body["phone_number"] = re.sub(r"[^+0-9]", "", body["phone_number"])

            if not re.match(_REGEX_PHONE_NUMBER, body["phone_number"]):
                return videon.response_json(400,
                                            {"message": "Phone number invalid"},
                                            event)

        # Currently not checking timezone and locale
        # Not sure what libs to use for validations
        # Timezone could potentially use pytz (https://pypi.org/project/pytz/)

        try:
            return videon.response_json(
                201,
                create_user_cognito(
                    body["name"],
                    body["email"],
                    body["password"],
                    body.get("phone_number"),
                    body["locale"],
                    body["zoneinfo"],
                ), event)
        except _cognito.exceptions.UsernameExistsException as err:
            return videon.response_json(400, {"message": "User already exists"},
                                        event)
        except _cognito.exceptions.InvalidParameterException as err:
            return videon.response_json(
                400, {"message": err.response["Error"]["Code"]}, event)
        except botocore.exceptions.ClientError as err:
            logger.error(err.response["Error"])
            return videon.response_json(
                400, {"message": err.response["Error"]["Code"]}, event)

    else:  # OPTIONS - CORS preflight
        return videon.response_cors(", ".join(supported_methods))


def find_users_cognito(search_attribute_name: str,
                       search_value: str,
                       starts_with=False,
                       pagination_token=None,
                       pagination_size=videon.PAGINATION_SIZE_DEFAULT):
    """Search the Cognito User Pool and return the results.

    https://docs.aws.amazon.com/cognito/latest/developerguide/how-to-manage-user-accounts.html
    https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListUsers.html
    """
    logger.info("search_attribute_name %s", search_attribute_name)
    logger.info("search_value %s", search_value)
    logger.info("starts_with %s", starts_with)
    logger.info("pagination_token %s", pagination_token)

    if starts_with is True:
        search_operator = "^="
    else:
        search_operator = "="

    filter = \
        f"{search_attribute_name} {search_operator} \"{search_value}\""

    # boto3 won't let us pass pagination token as None,
    # so we have to call it both ways.
    if pagination_token is not None:
        response = _cognito.list_users(UserPoolId=_cognito_user_pool_id,
                                       Limit=pagination_size,
                                       PaginationToken=pagination_token,
                                       Filter=filter)
    else:
        response = _cognito.list_users(UserPoolId=_cognito_user_pool_id,
                                       Limit=pagination_size,
                                       Filter=filter)

    logger.info("Cognito response %s", response)

    found_users = []

    # The JSON fields in the response are not a 1-to-1 match with the
    # inputs so we have to do some hijinks to get everything to fit.
    for user in response["Users"]:
        found_users.append({
            "user_guid":
                next((attribute["Value"]
                      for attribute in user["Attributes"]
                      if attribute["Name"] == "sub"), None),
            "name":
                next((attribute["Value"]
                      for attribute in user["Attributes"]
                      if attribute["Name"] == "name"), None),
            "email":
                next((attribute["Value"]
                      for attribute in user["Attributes"]
                      if attribute["Name"] == "email"), None),
            "email_verified":
                next(((attribute["Value"] == "true")
                      for attribute in user["Attributes"]
                      if attribute["Name"] == "email_verified"), False),
            "phone_number":
                next((attribute["Value"]
                      for attribute in user["Attributes"]
                      if attribute["Name"] == "phone_number"), None),
            "locale":
                next((attribute["Value"]
                      for attribute in user["Attributes"]
                      if attribute["Name"] == "locale"), None),
            "zoneinfo":
                next((attribute["Value"]
                      for attribute in user["Attributes"]
                      if attribute["Name"] == "zoneinfo"), None),
            "enabled":
                user["Enabled"],
            "status":
                user["UserStatus"],
            "created":
                user["UserCreateDate"],
            "last_modified":
                user["UserLastModifiedDate"],
        })

    return {
        "users": found_users,
        "pagination_token": response.get("PaginationToken")
    }


def find_users(user_guid: str,
               search_attribute_name: str,
               search_value: str = "",
               starts_with: bool = False,
               pagination_token: Union[str, None] = None,
               pagination_size: int = videon.PAGINATION_SIZE_DEFAULT,
               admin_view: bool = False):

    # Get list of ALL organizations user is a member of. We're doing this
    # because it should be faster/more scalable then getting all cognito users
    # and paginating this (as we're just getting a list of strings instead of
    # the entire cognito database). It also is optimized for the general user
    # base, who will only be members of <5 organizations.
    by_user_page = None
    found_orgs = []
    while True:
        payload = {"user_guid": user_guid}
        response = requests.get(f"{RESTAPI_URL_PATH}orgs",
                                params=payload,
                                headers=VIDEON_INTERNAL_HEADERS)
        assert response.status_code == 200

        response_json = response.json()
        found_orgs.extend(response_json["orgs"])
        by_user_page = response_json.get("pagination_token")

        if by_user_page is None:
            break

    logger.info(found_orgs)

    users = set()
    if not admin_view:
        # Remove access levels, and just get org guids
        orgs_guids: list = [org["org_guid"] for org in found_orgs]

        logger.info(orgs_guids)

        # Go through the orgs and get the users that are a member of the orgs
        # add those users to a set (remove duplicates)
        for guid in orgs_guids:
            response = requests.get(f"{RESTAPI_URL_PATH}orgs/{guid}/users",
                                    headers=VIDEON_INTERNAL_HEADERS)
            assert response.status_code == 200

            found_users = response.json()["users"]
            for user in found_users:
                users.add(user["user_guid"])

    pagination_offset: int = 0
    if pagination_token is not None:
        pagination_token: dict = json.loads(pagination_token)
        pagination_offset = pagination_token["o"]  # Offset
        pagination_token: str = pagination_token["t"]  # Token

    # Go through cognito users until we can fill the requested response
    found_users = []
    found_count = 0
    response_found_users = []
    while True:
        # Because just returning the cognito pagination token could cause some
        # users to be skipped (if we're done before the cognito page ends), we
        # are including a user offset along with the cognito pagination token
        user_offset = 0

        response = find_users_cognito(
            search_attribute_name,
            search_value,
            starts_with,
            pagination_token=pagination_token,
            pagination_size=videon.PAGINATION_SIZE_MAX)

        pagination_token = response.get("pagination_token")

        response_found_users = response["users"]
        for user in response_found_users[pagination_offset:]:
            user_offset += 1
            if user["user_guid"] in users or admin_view:
                found_users.append(user)
                found_count += 1

                if found_count >= pagination_size:  # Should never be above
                    break

        pagination_offset = 0

        # Exit if there is nothing else to paginate
        if pagination_token is None:
            break

    if pagination_token is None and len(response_found_users) == user_offset:
        response_pagination_token = None
    else:
        response_pagination_token = json.dumps({
            "t": pagination_token,
            "o": user_offset
        })

    return {"users": found_users, "pagination_token": response_pagination_token}


def create_user_cognito(name, email, password, phone_number, locale, zoneinfo):
    """Create user in the Cognito User Pool
    """

    logger.info("user_name %s", name)
    logger.info("user_email %s", email)
    logger.info("user_phone_number %s", phone_number)
    logger.info("user_locale %s", locale)
    logger.info("user_timezone %s", zoneinfo)

    user_attributes = {
        "name": name,
        "email": email,
        "locale": locale,
        "zoneinfo": zoneinfo
    }

    if phone_number is not None:
        user_attributes["phone_number"] = phone_number

    user_attrib_cognito = []
    for (attribute_name, attribute_value) in user_attributes.items():
        user_attrib_cognito.append({
            "Name": attribute_name,
            "Value": attribute_value
        })

    signup_res = _cognito.sign_up(ClientId=_cognito_client_id,
                                  Username=email,
                                  UserAttributes=user_attrib_cognito,
                                  Password=password)

    signup_delivery = signup_res["CodeDeliveryDetails"]

    return {
        "message": "User created successfully",
        "delivery_method": signup_delivery["DeliveryMedium"],
        "delivery_destination": signup_delivery["Destination"],
        "user_guid": signup_res["UserSub"]
    }
