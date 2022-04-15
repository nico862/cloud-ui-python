"""Request Handler for /invites/accept API Route

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

# Enable X-Ray Tracing
from aws_xray_sdk.core import patch_all
import boto3

import videon_shared as videon

patch_all()

logger = logging.getLogger()

dynamodb = boto3.client("dynamodb")

INVITES_TABLE_NAME = environ.get("INVITES_TABLE_NAME")

RESTAPI_URL_PATH = environ.get("RESTAPI_URL_PATH")

secret_manager = boto3.client("secretsmanager")
VIDEON_INTERNAL_AUTH_SECRET: str = secret_manager.get_secret_value(
    SecretId=environ["VIDEON_INTERNAL_AUTH_ARN"])["SecretString"]
VIDEON_INTERNAL_HEADERS = {
    "Authorization": "VIDEON_INTERNAL_AUTH " + VIDEON_INTERNAL_AUTH_SECRET
}


class AddUserError(Exception):
    pass


def lambda_handler(event, context):  # pylint: disable=unused-argument

    videon.setup_logging(logging.INFO, event)

    # Basic sanity checks (things that should never happen)
    # If these fail the API Gateway is probably misconfigured
    supported_methods = ("POST", "OPTIONS")
    assert event["httpMethod"] in supported_methods
    assert "AcceptInvite" in event["requestContext"]["operationName"]

    if event["httpMethod"] == "OPTIONS":
        return videon.response_cors(", ".join(supported_methods))

    response_json: dict = {"error_code": "UNHANDLED_CONDITION"}
    response_code: int = 500

    if event.get("body") is not None:
        try:
            body = videon.convert_request_body(event["body"])
        except videon.RequestBodyError as err:
            response_json = {"message": str(err)}
            return videon.response_json(400, response_json, event)

    if event["httpMethod"] == "POST":
        assert body is not None
        assert "invite_guid" in body

        invite_guid = body["invite_guid"]
        authorizer_user_guid = videon.get_authorizer_guid(event)

        try:
            response_json = accept_invite(invite_guid, authorizer_user_guid)
            response_code = 200
        except videon.ResourceNotFoundError as err:
            response_json = {"message": str(err)}
            response_code = 404
        except videon.PermissionsError:
            response_json = {
                "message": "User is not permitted to perform this action"
            }
            response_code = 403
        except AddUserError as err:
            error_json = json.loads(str(err))
            response_code = error_json.get("status_code")
            failure_message = error_json.get("message")
            response_json = {
                "message": "Failed to add user to organization. "\
                f"Failed with: {failure_message}"
            }

    return videon.response_json(response_code, response_json, event)


def accept_invite(invite_guid: str, authorizer_user_guid: str) -> dict:
    get_user_url = f"{RESTAPI_URL_PATH}users/{authorizer_user_guid}"
    get_user_response = requests.get(get_user_url,
                                     headers=VIDEON_INTERNAL_HEADERS)

    if get_user_response.status_code == 404:
        raise videon.PermissionsError()

    assert get_user_response.status_code == 200
    get_user_response_json = get_user_response.json().get("user")
    assert get_user_response_json is not None

    user_email = get_user_response_json.get("email", "")
    user_email = user_email.lower()

    get_invite_response = dynamodb.get_item(
        TableName=INVITES_TABLE_NAME,
        Key={"invite_guid": {
            "S": invite_guid
        }},
        ConsistentRead=True)
    logger.info("DynamoDB GET invite ID %s response: %s", invite_guid,
                get_invite_response)

    invite = get_invite_response.get("Item")
    if not invite:
        raise videon.ResourceNotFoundError("Invite not found")

    invite_email = invite["user_email"]["S"]
    if user_email != invite_email:
        raise videon.PermissionsError()

    org_guid = invite["org_guid"]["S"]
    access_level = invite["access"]["N"]

    post_request_body = json.dumps({
        "user_guid": authorizer_user_guid,
        "access": int(access_level)
    })
    post_orgs_user_url = f"{RESTAPI_URL_PATH}orgs/{org_guid}/users"
    post_orgs_user_response = requests.post(post_orgs_user_url,
                                            headers=VIDEON_INTERNAL_HEADERS,
                                            data=post_request_body)

    if post_orgs_user_response.status_code != 200:
        failure_message = post_orgs_user_response.json().get("message")
        error_str = json.dumps({
            "status_code": post_orgs_user_response.status_code,
            "message": failure_message
        })
        raise AddUserError(error_str)

    dynamodb.delete_item(TableName=INVITES_TABLE_NAME,
                         Key={"invite_guid": {
                             "S": invite_guid
                         }})

    return {"message": "Organization joined successfully"}
