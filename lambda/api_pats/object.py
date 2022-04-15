"""Request Handler for /pat/{token_guid} API Route

This is implemented as a Lambda Proxy integration.  The function is
responsible for validating the input, and sending a properly-formatted
response.  (Failure to do so will be a 5xx error for the client)

https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
https://docs.aws.amazon.com/apigateway/latest/developerguide/handle-errors-in-lambda-integration.html
"""
import logging
from os import environ

from aws_xray_sdk.core import patch_all  # Enable X-Ray Tracing
import boto3

import videon_shared as videon

patch_all()

dynamodb = boto3.client("dynamodb")

logger = logging.getLogger()

TOKEN_TABLE_NAME = environ.get("PERSONAL_ACCESS_TOKENS_TABLE_NAME")
RESTAPI_URL_PATH = environ.get("RESTAPI_URL_PATH")
COGNITO_USER_MANAGEMENT_GROUP_NAME = environ.get(
    "COGNITO_USER_MANAGEMENT_GROUP_NAME")


def lambda_handler(event, context):  # pylint: disable=unused-argument
    videon.setup_logging(logging.INFO, event)

    # Basic sanity checks (things that should never happen)
    # If these fail the API Gateway is probably misconfigured
    supported_methods = ("GET", "DELETE", "OPTIONS")
    assert event["httpMethod"] in supported_methods
    assert "PersonalAccessToken" in event["requestContext"]["operationName"]

    if event["httpMethod"] == "OPTIONS":
        return videon.response_cors(", ".join(supported_methods))

    authorizer_user_guid = videon.get_authorizer_guid(event)
    token_guid = event["pathParameters"]["token_guid"]

    response_json = {"error_code": "UNHANDLED_CONDITION"}
    response_code = 500

    query_string_params = event.get("queryStringParameters")
    if query_string_params is not None:
        target_user_guid = query_string_params.get("user_guid",
                                                   authorizer_user_guid)
        if target_user_guid == "myself":
            target_user_guid = authorizer_user_guid

        if target_user_guid != authorizer_user_guid:
            user_groups = videon.get_user_groups(event)

            if COGNITO_USER_MANAGEMENT_GROUP_NAME not in user_groups:
                response_json = {
                    "message": "User does not have permission to "
                               "perform this action"
                }
                response_code = 403
                return videon.response_json(response_code, response_json, event)
    else:
        target_user_guid = authorizer_user_guid

    try:
        if event["httpMethod"] == "GET":
            response_json = get_token(token_guid, target_user_guid)
        else:  # (DELETE)
            response_json = delete_token(token_guid, target_user_guid)
        response_code = 200
    except videon.ResourceNotFoundError:
        response_json = {"message": "Token not found"}
        response_code = 404

    return videon.response_json(response_code, response_json, event)


def get_token(token_guid, user_guid):
    get_response = dynamodb.get_item(TableName=TOKEN_TABLE_NAME,
                                     Key={"token_guid": {
                                         "S": token_guid
                                     }},
                                     ConsistentRead=True)

    logger.info("DynamoDB GET personal access token GUID %s response: %s",
                token_guid, get_response)

    token = get_response.get("Item")

    if not token or token["user_guid"]["S"] != user_guid:
        raise videon.ResourceNotFoundError

    return {
        "personal_access_token": {
            "token_prefix": token["token_prefix"]["S"],
            "issued": token["issued"]["S"],
            "expires": token["expires"]["S"],
            "comment": token["comment"]["S"],
            "last_used": token["last_used"]["S"],
        }
    }


def delete_token(token_guid, user_guid):
    get_response = dynamodb.get_item(TableName=TOKEN_TABLE_NAME,
                                     Key={"token_guid": {
                                         "S": token_guid
                                     }},
                                     ConsistentRead=True)

    token = get_response.get("Item")

    if not token or token["user_guid"]["S"] != user_guid:
        raise videon.ResourceNotFoundError

    if "token_hash" in token:
        logger.info(
            "Deleting personal access token GUID %s and "
            "corresponding transaction entry", token_guid)

        # Must delete both the normal entry and token hash as primary key entry
        token_hash = token["token_hash"]["S"]
        token_hash_pk = "token_hash#" + token_hash

        dynamodb.transact_write_items(TransactItems=[
            {
                "Delete": {
                    "TableName": TOKEN_TABLE_NAME,
                    "Key": {
                        "token_guid": {
                            "S": token_hash_pk
                        }
                    }
                }
            },
            {
                "Delete": {
                    "TableName": TOKEN_TABLE_NAME,
                    "Key": {
                        "token_guid": {
                            "S": token_guid
                        }
                    }
                }
            },
        ],)
    else:
        logger.info("Deleting personal access token GUID %s", token_guid)
        dynamodb.delete_item(TableName=TOKEN_TABLE_NAME,
                             Key={"token_guid": {
                                 "S": token_guid
                             }})

    return {"message": "Token successfully revoked"}
