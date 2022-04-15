"""Request Handler for /invites/{invite_guid} API Route

This is implemented as a Lambda Proxy integration.  The function is
responsible for validating the input, and sending a properly-formatted
response.  (Failure to do so will be a 5xx error for the client.)

https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
https://docs.aws.amazon.com/apigateway/latest/developerguide/handle-errors-in-lambda-integration.html
"""
import logging
from os import environ
import requests
from urllib.parse import unquote

# Enable X-Ray Tracing
from aws_xray_sdk.core import patch_all
import boto3

import videon_shared as videon

patch_all()

logger = logging.getLogger()

dynamodb = boto3.client("dynamodb")

INVITES_TABLE_NAME = environ.get("INVITES_TABLE_NAME")

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
    supported_methods = ("GET", "DELETE", "OPTIONS")
    assert event["httpMethod"] in supported_methods
    assert "Invite" in event["requestContext"]["operationName"]
    assert event["pathParameters"].get("invite_guid") is not None

    if event["httpMethod"] == "OPTIONS":
        return videon.response_cors(", ".join(supported_methods))

    response_json = {"error_code": "UNHANDLED_CONDITION"}
    response_code = 500

    authorizer_user_guid = videon.get_authorizer_guid(event)
    authorizer_user_groups = videon.get_user_groups(event)

    invite_guid = unquote(event["pathParameters"]["invite_guid"])

    try:
        if event["httpMethod"] == "GET":
            response_json = get_invite(invite_guid, authorizer_user_guid,
                                       authorizer_user_groups)
        elif event["httpMethod"] == "DELETE":
            response_json = delete_invite(invite_guid, authorizer_user_guid,
                                          authorizer_user_groups)
        response_code = 200
    except (videon.ResourceNotFoundError, videon.PermissionsError):
        response_json = {
            "message": "Invite does not exist or user is " \
                       "not permitted to perform this action"
        }
        response_code = 404

    return videon.response_json(response_code, response_json, event)


def get_invite(invite_guid: str, authorizer_user_guid: str,
               authorizer_user_groups) -> dict:
    get_invite_response = dynamodb.get_item(
        TableName=INVITES_TABLE_NAME,
        Key={"invite_guid": {
            "S": invite_guid
        }},
        ConsistentRead=True)

    logger.info("DynamoDB GET invite %s response: %s", invite_guid,
                get_invite_response)

    invite = get_invite_response.get("Item")

    if not invite:
        raise videon.ResourceNotFoundError

    invite_email = invite["user_email"]["S"]
    org_guid = invite["org_guid"]["S"]

    get_user_url = f"{RESTAPI_URL_PATH}users/{authorizer_user_guid}"
    get_user_response = requests.get(get_user_url,
                                     headers=VIDEON_INTERNAL_HEADERS)

    assert get_user_response.status_code == 200
    get_user_response_json = get_user_response.json().get("user")
    assert get_user_response_json is not None

    authorizer_email = get_user_response_json.get("email")

    is_org_management = (COGNITO_ORG_MANAGEMENT_GROUP_NAME
                         in authorizer_user_groups)

    if authorizer_email != invite_email and not is_org_management:
        videon.validate_user_org_access(authorizer_user_guid, org_guid,
                                        videon.Permissions.ADMIN,
                                        RESTAPI_URL_PATH,
                                        VIDEON_INTERNAL_HEADERS)

    get_org_url = f"{RESTAPI_URL_PATH}orgs/{org_guid}"
    get_org_response = requests.get(get_org_url,
                                    headers=VIDEON_INTERNAL_HEADERS)
    assert get_org_response.status_code == 200
    org_name = get_org_response.json()["org"]["org_name"]

    return {
        "invite": {
            "invite_guid": invite_guid,
            "org_name": org_name,
            "org_guid": org_guid,
            "target_email": invite_email,
            "access": int(invite["access"]["N"]),
        }
    }


def delete_invite(invite_guid: str, authorizer_user_guid: str,
                  authorizer_user_groups: list) -> dict:
    get_response = dynamodb.get_item(TableName=INVITES_TABLE_NAME,
                                     Key={"invite_guid": {
                                         "S": invite_guid
                                     }},
                                     ConsistentRead=True)

    logger.info("DynamoDB GET invite %s response: %s", invite_guid,
                get_response)

    invite = get_response.get("Item")

    if not invite:
        raise videon.ResourceNotFoundError

    org_guid = invite["org_guid"]["S"]

    if COGNITO_ORG_MANAGEMENT_GROUP_NAME not in authorizer_user_groups:
        videon.validate_user_org_access(authorizer_user_guid, org_guid,
                                        videon.Permissions.ADMIN,
                                        RESTAPI_URL_PATH,
                                        VIDEON_INTERNAL_HEADERS)

    dynamodb.delete_item(TableName=INVITES_TABLE_NAME,
                         Key={"invite_guid": {
                             "S": invite_guid
                         }})

    return {"message": "Successfully deleted invite"}
