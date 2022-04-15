"""Request Handler for /users/{user_guid} API Route

This is implemented as a Lambda Proxy integration.  The function is
responsible for validating the input, and sending a properly-formatted
response.  (Failure to do so will be a 5xx error for the client.)

https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
https://docs.aws.amazon.com/apigateway/latest/developerguide/handle-errors-in-lambda-integration.html
"""

import boto3
import logging
import videon_shared as videon

from os import environ

# Enable X-Ray Tracing
from aws_xray_sdk.core import patch_all

patch_all()

_cognito = boto3.client("cognito-idp")
_cognito_user_pool_id = environ.get("COGNITO_USER_POOL_ID")

COGNITO_USER_MANAGEMENT_GROUP_NAME = environ.get(
    "COGNITO_USER_MANAGEMENT_GROUP_NAME")

logger = logging.getLogger()


def lambda_handler(event, context):  # pylint: disable=unused-argument

    videon.setup_logging(logging.INFO, event)

    # If this fails the API gateway is misconfigured
    supported_methods = ("GET", "PATCH", "DELETE", "OPTIONS")
    assert event["httpMethod"] in supported_methods

    user_guid = event["pathParameters"]["user_guid"]

    # Using .get() because both OPTIONS requests, and requests using the
    # VIDOEN_INTERNAL_AUTH method will cause no values to be in authorizer
    if event["httpMethod"] in ("GET", "PATCH", "DELETE"):
        authorizer_guid = videon.get_authorizer_guid(event)
        if user_guid == "myself":
            user_guid = authorizer_guid

    authorizer_user_groups = videon.get_user_groups(event)
    is_user_admin = COGNITO_USER_MANAGEMENT_GROUP_NAME in authorizer_user_groups

    if event["httpMethod"] == "GET":
        logger.info("GET Method...")

        try:
            user_data = find_user_cognito(user_guid)
        except _cognito.exceptions.UserNotFoundException as err:
            return videon.response_json(
                404, {"message": "Unable to locate user; User does not exist"},
                event=event)

        return videon.response_json(200, user_data, event=event)
    elif event["httpMethod"] == "PATCH":
        logger.info("PATCH Method...")

        if authorizer_guid != user_guid and not is_user_admin:
            return videon.response_json(
                403,
                {"message": "Unable to modify user (insufficient permissions)"},
                event)

        try:
            body = videon.convert_request_body(event["body"])
        except videon.RequestBodyError as err:
            return videon.response_json(400, {"message": str(err)}, event)

        try:
            update_res = update_user_cognito(user_guid, body)
        except _cognito.exceptions.UserNotFoundException as err:
            return videon.response_json(
                404, {"message": "Unable to locate user; User does not exist"},
                event)

        return videon.response_json(200, update_res, event)
    elif event["httpMethod"] == "DELETE":
        logger.info("DELETE Method...")

        if authorizer_guid != user_guid and not is_user_admin:
            return videon.response_json(
                403,
                {"message": "Unable to delete user (insufficient permissions)"},
                event)

        try:
            body = videon.convert_request_body(event["body"])
        except videon.RequestBodyError as err:
            return videon.response_json(400, {"message": str(err)}, event)

        reason = body["reason"] if "reason" in body else ""

        try:
            delete_res = delete_user_cognito(user_guid, reason)
        except _cognito.exceptions.UserNotFoundException as err:
            return videon.response_json(
                404, {"message": "Unable to locate user; User does not exist"},
                event)

        return videon.response_json(200, delete_res, event)
    else:  # OPTIONS - CORS preflight
        return videon.response_cors(", ".join(supported_methods))


def find_user_cognito(user_guid):
    user = _cognito.admin_get_user(UserPoolId=_cognito_user_pool_id,
                                   Username=user_guid)

    found_user = {
        "name":
            next((attribute["Value"]
                  for attribute in user["UserAttributes"]
                  if attribute["Name"] == "name"), None),
        "email":
            next((attribute["Value"]
                  for attribute in user["UserAttributes"]
                  if attribute["Name"] == "email"), None),
        "email_verified":
            next((bool(attribute["Value"])
                  for attribute in user["UserAttributes"]
                  if attribute["Name"] == "email_verified"), False),
        "phone_number":
            next((attribute["Value"]
                  for attribute in user["UserAttributes"]
                  if attribute["Name"] == "phone_number"), None),
        "phone_number_verified":
            next((attribute["Value"]
                  for attribute in user["UserAttributes"]
                  if attribute["Name"] == "phone_number_verified"), False),
        "locale":
            next((attribute["Value"]
                  for attribute in user["UserAttributes"]
                  if attribute["Name"] == "locale"), None),
        "zoneinfo":
            next((attribute["Value"]
                  for attribute in user["UserAttributes"]
                  if attribute["Name"] == "zoneinfo"), None),
        "enabled":
            user["Enabled"],
        "status":
            user["UserStatus"],
        "created":
            user["UserCreateDate"],
        "last_modified":
            user["UserLastModifiedDate"],
        "mfa_sms_enabled":
            False,
        "mfa_totp_enabled":
            False
    }

    # We currently don't have a MFA system setup, so when we do,
    # we'll need to update
    if "UserMFASettingList" in user:
        pass

    return {"user": found_user}


def update_user_cognito(user_guid, user_options):
    editable_attributes = ("name", "email", "phone_number", "locale",
                           "zoneinfo")
    cognito_formatted_attributes = []

    logger.info({"message": user_options})

    for key, value in user_options.items():
        if key in editable_attributes:
            cognito_formatted_attributes.append({"Name": key, "Value": value})

    response = _cognito.admin_update_user_attributes(
        UserPoolId=_cognito_user_pool_id,
        Username=user_guid,
        UserAttributes=cognito_formatted_attributes)

    if "enabled" in user_options:
        current_user = find_user_cognito(user_guid)

        # If passing in the same state as current state, ignore
        if current_user["enabled"] != user_options["enabled"]:
            if user_options["enabled"]:  # If enabling
                res = _cognito.admin_enable_user(
                    UserPoolId=_cognito_user_pool_id, Username=user_guid)
            else:  # If disabling
                res = _cognito.admin_disable_user(
                    UserPoolId=_cognito_user_pool_id, Username=user_guid)
            logger.info(res)
    logger.info(response)

    return {"message": "User was successfully modified"}


def delete_user_cognito(user_guid, reason):
    _cognito.admin_delete_user(UserPoolId=_cognito_user_pool_id,
                               Username=user_guid)

    # TODO: Maybe add more information (pseudonymized)
    logger.info("User %s deleted successfully. Reason: %s", user_guid, reason)

    return {}
