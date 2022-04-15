"""Request Handler for /invites API Route

This is implemented as a Lambda Proxy integration.  The function is
responsible for validating the input, and sending a properly-formatted
response.  (Failure to do so will be a 5xx error for the client.)

https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
https://docs.aws.amazon.com/apigateway/latest/developerguide/handle-errors-in-lambda-integration.html
"""
import json
import logging
from os import environ
import requests
from requests.structures import CaseInsensitiveDict
from typing import Union

# Enable X-Ray Tracing
from aws_xray_sdk.core import patch_all
import boto3
import botocore.exceptions

import videon_shared as videon

patch_all()

logger = logging.getLogger()

dynamodb = boto3.client("dynamodb")
dynamo_paginator_query = dynamodb.get_paginator("query")

ses = boto3.client("ses")

INVITES_TABLE_NAME = environ.get("INVITES_TABLE_NAME")
INVITES_EMAIL_TEMPLATE_NAME = environ.get("INVITES_EMAIL_TEMPLATE_NAME")
EMAIL_ADDR_NOREPLY = environ.get("EMAIL_ADDR_NOREPLY")

COGNITO_ORG_MANAGEMENT_GROUP_NAME = environ.get(
    "COGNITO_ORG_MANAGEMENT_GROUP_NAME")

RESTAPI_URL_PATH = environ.get("RESTAPI_URL_PATH")

secret_manager = boto3.client("secretsmanager")
VIDEON_INTERNAL_AUTH_SECRET: str = secret_manager.get_secret_value(
    SecretId=environ["VIDEON_INTERNAL_AUTH_ARN"])["SecretString"]
VIDEON_INTERNAL_HEADERS = {
    "Authorization": "VIDEON_INTERNAL_AUTH " + VIDEON_INTERNAL_AUTH_SECRET
}


def lambda_handler(event, context):  # pylint: disable=unused-argument

    videon.setup_logging(logging.INFO, event)

    # Basic sanity checks (things that should never happen)
    # If these fail the API Gateway is probably misconfigured
    supported_methods = ("GET", "POST", "OPTIONS")
    assert event["httpMethod"] in supported_methods
    assert "Invite" in event["requestContext"]["operationName"]

    if event["httpMethod"] == "OPTIONS":
        return videon.response_cors(", ".join(supported_methods))

    response_json = {"error_code": "UNHANDLED_CONDITION"}
    response_code = 500

    authorizer_user_guid = videon.get_authorizer_guid(event)
    authorizer_user_groups = videon.get_user_groups(event)

    if event.get("body") is not None:
        try:
            body = videon.convert_request_body(event["body"])
        except videon.RequestBodyError as err:
            response_json = {"message": str(err)}
            return videon.response_json(400, response_json, event)

    if event["httpMethod"] == "GET":
        query_string_params = event.get("queryStringParameters")
        if query_string_params is not None:
            org_guid = query_string_params.get("org_guid")
            pagination_token = query_string_params.get("pagination_token")
            pagination_size = query_string_params.get("pagination_size")

            try:
                pagination_size = videon.validate_pagination_size(
                    pagination_size)
            except (TypeError, ValueError) as err:
                response_json = {
                    "message": "Invalid pagination size. " + str(err)
                }
                return videon.response_json(400, response_json, event)
        else:
            org_guid = None
            pagination_token = None
            pagination_size = videon.PAGINATION_SIZE_DEFAULT

        # Set up encryption key for pagination token
        pagination_encryption_key = videon.pagination_encryption_key(
            context.function_name, authorizer_user_guid,
            videon.is_internal_auth(event))

        try:
            decrypted_pagination_token = videon.pagination_decrypt(
                pagination_token, pagination_encryption_key)

            response_json = get_invites(authorizer_user_guid, org_guid,
                                        authorizer_user_groups,
                                        decrypted_pagination_token,
                                        pagination_size)

            response_json["pagination_token"] = videon.pagination_encrypt(
                response_json.get("pagination_token"),
                pagination_encryption_key)

            response_code = 200
        except videon.PaginationTokenError:
            response_code = 400
            response_json = {"message": "Invalid pagination token"}
        except videon.PermissionsError as err:
            response_code = 403
            response_json = {"message": str(err)}
        except videon.ResourceNotFoundError:
            response_code = 404
            response_json = {
                "message":
                    "Organization does not exist or user is "\
                    "not permitted to perform this action"
            }

    elif event["httpMethod"] == "POST":
        assert "target_email" in body
        assert "access" in body
        assert "headers" in event

        target_email = body["target_email"]
        org_guid = body.get("org_guid")

        headers = CaseInsensitiveDict(event["headers"])
        if headers is not None and org_guid is None:
            org_guid = headers.get("Org-Guid")

        if org_guid is None:
            response_json = {
                "message": "Missing required request parameters: " \
                           "[Org-Guid or org_guid]"
            }
            response_code = 400
            return videon.response_json(response_code, response_json, event)

        try:
            access = videon.validate_numeric_param_value(body["access"],
                                                         integer=True)
            assert access in videon.Permissions
        except (TypeError, ValueError, AssertionError) as err:
            response_json = {"message": "Invalid access level. " + str(err)}
            return videon.response_json(400, response_json, event)

        try:
            response_json = create_invite(authorizer_user_guid,
                                          authorizer_user_groups, target_email,
                                          org_guid, access)
            response_code = 201
        except videon.PermissionsError as err:
            response_code = 403
            response_json = {"message": str(err)}
        except videon.ResourceNotFoundError:
            response_code = 404
            response_json = {
                "message":
                    "Organization does not exist or user is "\
                    "not permitted to perform this action"
            }
        except videon.ResourceExistsError as err:
            response_code = 409
            response_json = {"message": str(err)}

    return videon.response_json(response_code, response_json, event)


def get_invites(authorizer_user_guid: str, org_guid: str,
                authorizer_user_groups: list, pagination_token: Union[str,
                                                                      None],
                pagination_size: int) -> dict:

    pagination_config = {}
    pagination_config["MaxItems"] = pagination_size
    if pagination_token is not None:
        pagination_config["StartingToken"] = pagination_token

    org_guid_specified = False
    if org_guid is None:
        get_user_url = f"{RESTAPI_URL_PATH}users/{authorizer_user_guid}"
        get_user_response = requests.get(get_user_url,
                                         headers=VIDEON_INTERNAL_HEADERS)

        assert get_user_response.status_code == 200
        get_user_response_json = get_user_response.json().get("user")
        assert get_user_response_json is not None

        user_email = get_user_response_json.get("email")

        if user_email is None:
            return {"invites": []}

        index_name = "user_email"
        exp_attr_values = {":user_email": {"S": user_email.lower()}}
        key_condition_exp = "user_email = :user_email"
    else:
        org_guid_specified = True
        if COGNITO_ORG_MANAGEMENT_GROUP_NAME not in authorizer_user_groups:
            videon.validate_user_org_access(authorizer_user_guid, org_guid,
                                            videon.Permissions.ADMIN,
                                            RESTAPI_URL_PATH,
                                            VIDEON_INTERNAL_HEADERS)
        index_name = "org_guid"
        exp_attr_values = {":org_guid": {"S": org_guid}}
        key_condition_exp = "org_guid = :org_guid"

        # Get the org name now, so we don't repeatedly get the org name
        # for each invite
        get_org_url = f"{RESTAPI_URL_PATH}orgs/{org_guid}"
        get_org_response = requests.get(get_org_url,
                                        headers=VIDEON_INTERNAL_HEADERS)
        assert get_org_response.status_code == 200
        org_name = get_org_response.json()["org"]["org_name"]

    try:
        query_response = dynamo_paginator_query.paginate(
            TableName=INVITES_TABLE_NAME,
            IndexName=index_name,
            KeyConditionExpression=key_condition_exp,
            ExpressionAttributeValues=exp_attr_values,
            PaginationConfig=pagination_config).build_full_result()
    except botocore.exceptions.ParamValidationError as err:
        # "Invalid type for parameter ExclusiveStartKey" in the error message
        # means that the pagination token was invalid
        if "ExclusiveStartKey" in str(err):
            raise videon.PaginationTokenError from err
        raise err

    logger.info("DynamoDB GET invites response: %s", json.dumps(query_response))

    invites = {"invites": []}

    for item in query_response["Items"]:
        if not org_guid_specified:
            invite_org_guid = item["org_guid"]["S"]
            get_org_url = f"{RESTAPI_URL_PATH}orgs/{invite_org_guid}"
            get_org_response = requests.get(get_org_url,
                                            headers=VIDEON_INTERNAL_HEADERS)
            assert get_org_response.status_code == 200
            org_name = get_org_response.json()["org"]["org_name"]

        invites["invites"].append({
            "invite_guid": item["invite_guid"]["S"],
            "org_name": org_name,
            "org_guid": item["org_guid"]["S"],
            "target_email": item["user_email"]["S"],
            "access": int(item["access"]["N"]),
        })

    invites["pagination_token"] = query_response.get("NextToken")

    return invites


def create_invite(authorizer_user_guid: str, authorizer_user_groups: list,
                  target_email: str, org_guid: str, access_level: int) -> dict:
    if COGNITO_ORG_MANAGEMENT_GROUP_NAME not in authorizer_user_groups:
        videon.validate_user_org_access(authorizer_user_guid, org_guid,
                                        videon.Permissions.ADMIN,
                                        RESTAPI_URL_PATH,
                                        VIDEON_INTERNAL_HEADERS)

    # Make guid case insensitive
    target_email = target_email.lower()
    invite_guid = videon.generate_membership_guid(org_guid, target_email)

    try:
        dynamodb.put_item(
            TableName=INVITES_TABLE_NAME,
            Item={
                "invite_guid": {
                    "S": invite_guid
                },
                "user_email": {
                    "S": target_email
                },
                "org_guid": {
                    "S": org_guid
                },
                "access": {
                    "N": str(access_level)
                },
            },
            ConditionExpression="attribute_not_exists(invite_guid)")
    except dynamodb.exceptions.ConditionalCheckFailedException as err:
        raise videon.ResourceExistsError("Invite already exists") from err

    ses.send_templated_email(Source=EMAIL_ADDR_NOREPLY,
                             Destination={"ToAddresses": [target_email]},
                             Template=INVITES_EMAIL_TEMPLATE_NAME,
                             TemplateData="{}")

    return {"message": "Invite sent successfully", "invite_guid": invite_guid}
