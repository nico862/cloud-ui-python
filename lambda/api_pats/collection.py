"""Request Handler for /pat API Route

This is implemented as a Lambda Proxy integration.  The function is
responsible for validating the input, and sending a properly-formatted
response.  (Failure to do so will be a 5xx error for the client)

https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
https://docs.aws.amazon.com/apigateway/latest/developerguide/handle-errors-in-lambda-integration.html
"""
import datetime
import json
import logging
from os import environ
import uuid
import requests
import secrets

from aws_xray_sdk.core import patch_all  # Enable X-Ray Tracing
import boto3
import botocore.exceptions

import videon_shared as videon

patch_all()

dynamodb = boto3.client("dynamodb")
dynamo_paginator_query = dynamodb.get_paginator("query")

logger = logging.getLogger()

TOKEN_TABLE_NAME = environ.get("PERSONAL_ACCESS_TOKENS_TABLE_NAME")
RESTAPI_URL_PATH = environ.get("RESTAPI_URL_PATH")
COGNITO_USER_MANAGEMENT_GROUP_NAME = environ.get(
    "COGNITO_USER_MANAGEMENT_GROUP_NAME")

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
    supported_methods = ("GET", "POST", "PATCH", "OPTIONS")
    assert event["httpMethod"] in supported_methods
    assert "PersonalAccessToken" in event["requestContext"]["operationName"]

    if event["httpMethod"] == "OPTIONS":
        return videon.response_cors(", ".join(supported_methods))

    authorizer_user_guid = videon.get_authorizer_guid(event)

    response_json = {"error_code": "UNHANDLED_CONDITION"}
    response_code = 500

    if event.get("body") is not None:
        try:
            body = videon.convert_request_body(event["body"])
        except videon.RequestBodyError as err:
            response_json = {"message": str(err)}
            response_code = 400
            return videon.response_json(response_code, response_json, event)

    if event["httpMethod"] == "GET":
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
                    return videon.response_json(response_code, response_json,
                                                event)

            pagination_token = query_string_params.get("pagination_token")
            pagination_size = query_string_params.get("pagination_size")

            try:
                pagination_size = videon.validate_pagination_size(
                    pagination_size)
            except (TypeError, ValueError) as err:
                response_json = {
                    "message": "Invalid pagination size. " + str(err)
                }
                response_code = 400
                return videon.response_json(response_code, response_json, event)
        else:
            target_user_guid = authorizer_user_guid
            pagination_size = videon.PAGINATION_SIZE_DEFAULT
            pagination_token = None

        # Set up encryption key for pagination token
        pagination_encryption_key = videon.pagination_encryption_key(
            context.function_name, authorizer_user_guid,
            videon.is_internal_auth(event))

        try:
            decrypted_pagination_token = videon.pagination_decrypt(
                pagination_token, pagination_encryption_key)

            response_json = get_tokens(target_user_guid, pagination_size,
                                       decrypted_pagination_token)

            response_json["pagination_token"] = videon.pagination_encrypt(
                response_json.get("pagination_token"),
                pagination_encryption_key)

            response_code = 200
        except videon.PaginationTokenError:
            response_code = 400
            response_json = {"message": "Invalid pagination token"}

    elif event["httpMethod"] == "POST":
        assert authorizer_user_guid is not None
        assert "token_lifespan_days" in body

        user_comment = body.get("comment", "")

        response_json = create_token(body["token_lifespan_days"],
                                     authorizer_user_guid, user_comment)
        response_code = 201

    else:  # (PATCH)
        assert "token_hash" in body

        if videon.is_internal_auth(event):
            try:
                response_json = verify_token(body["token_hash"])
                response_code = 200
            except videon.PersonalAccessTokenError as err:
                response_code = 401
                response_json = {"error_code": str(err)}
            except videon.ResourceNotFoundError:
                response_code = 404
                response_json = {"error_code": "NO_MATCH"}
            except videon.UserStatusError as err:
                response_code = 409
                response_json = {"error_code": str(err)}
        else:
            response_code = 403
            response_json = {
                "message":
                    "User does not have permission to perform this action"
            }

    return videon.response_json(response_code, response_json, event)


def get_tokens(target_user_guid, pagination_size, decrypted_pagination_token):
    pagination_config = {}
    pagination_config["MaxItems"] = pagination_size
    if decrypted_pagination_token is not None:
        pagination_config["StartingToken"] = decrypted_pagination_token

    user_guid_exp_attr_values = {":user_guid": {"S": target_user_guid}}
    # 'comment' is a reserved keyword in DynamoDB
    comment_exp_attr_names = {"#c": "comment"}

    try:
        response = dynamo_paginator_query.paginate(
            TableName=TOKEN_TABLE_NAME,
            IndexName="user_guid",
            Select="SPECIFIC_ATTRIBUTES",
            ProjectionExpression=
            "token_guid,token_prefix,issued,expires,#c,last_used",
            KeyConditionExpression="user_guid = :user_guid",
            ExpressionAttributeValues=user_guid_exp_attr_values,
            ExpressionAttributeNames=comment_exp_attr_names,
            PaginationConfig=pagination_config).build_full_result()
    except botocore.exceptions.ParamValidationError as err:
        # "Invalid type for parameter ExclusiveStartKey" in the error message
        # means that the pagination token was invalid
        if "ExclusiveStartKey" in str(err):
            raise videon.PaginationTokenError from err
        raise err

    logger.info("DynamoDB GET PATs response: %s", json.dumps(response))

    tokens = {"personal_access_tokens": []}
    for item in response["Items"]:
        tokens["personal_access_tokens"].append({
            "token_guid": item["token_guid"]["S"],
            "token_prefix": item["token_prefix"]["S"],
            "issued": item["issued"]["S"],
            "expires": item["expires"]["S"],
            "comment": item["comment"]["S"],
            "last_used": item["last_used"]["S"]
        })

    tokens["pagination_token"] = response.get("NextToken")

    return tokens


def create_token(token_lifespan_days, user_guid, user_comment):
    token_guid = str(uuid.uuid4())
    token_value = secrets.token_urlsafe()

    # Generate timestamps - Using current time with seconds precision
    issued_datetime = datetime.datetime.utcnow().replace(microsecond=0)
    issued_timestamp = issued_datetime.isoformat() + "Z"

    expires_datetime = issued_datetime + datetime.timedelta(
        days=token_lifespan_days)
    expires_timestamp = expires_datetime.isoformat() + "Z"

    logger.info("Creating personal access token GUID: %s for user GUID: %s",
                token_guid, user_guid)

    # We need to ensure both token GUID and token hash are unique
    # To do this, we will take advantage of transactions[1] and retry once
    # when the token guid and/or token already exist in the table
    # [1]:
    # https://aws.amazon.com/blogs/database/simulating-amazon-dynamodb-unique-constraints-using-transactions/
    write_attempts = 0
    max_write_attempts = 2
    while write_attempts < max_write_attempts:
        write_attempts += 1

        token_prefix = token_value[0:5]
        token_hash = videon.get_sha256_hash(token_value)
        token_hash_pk = "token_hash#" + token_hash

        try:
            dynamodb.transact_write_items(
                TransactItems=[
                    {
                        "Put": {
                            "TableName":
                                TOKEN_TABLE_NAME,
                            "Item": {
                                "token_guid": {
                                    "S": token_guid
                                },
                                "token_hash": {
                                    "S": token_hash
                                },
                                "user_guid": {
                                    "S": user_guid
                                },
                                "token_prefix": {
                                    "S": token_prefix
                                },
                                "issued": {
                                    "S": issued_timestamp
                                },
                                "expires": {
                                    "S": expires_timestamp
                                },
                                # Initialize last_used as an empty string
                                "last_used": {
                                    "S": ""
                                },
                                "comment": {
                                    "S": user_comment
                                },
                                # Initialize expiry email reminder count at 0
                                "expiry_reminder_count": {
                                    "N": "0"
                                }
                            },
                            "ConditionExpression":
                                "attribute_not_exists(token_guid)"
                        },
                    },
                    {
                        "Put": {
                            "TableName":
                                TOKEN_TABLE_NAME,
                            "Item": {
                                "token_guid": {
                                    "S": token_hash_pk
                                }
                            },
                            "ConditionExpression":
                                "attribute_not_exists(token_guid)"
                        }
                    },
                ],)
        except dynamodb.exceptions.TransactionCanceledException as err:
            cancellation_reasons = err.response["CancellationReasons"]

            # Something else happened so go back to raising the error
            if len(cancellation_reasons) != 2:
                raise err

            conditional_check_error = False
            if cancellation_reasons[0]["Code"] == "ConditionalCheckFailed":
                # Regenerate the token GUID because it wasn't unique
                token_guid = str(uuid.uuid4())
                conditional_check_error = True

            if cancellation_reasons[1]["Code"] == "ConditionalCheckFailed":
                # Regenerate the token because it wasn't unique
                token_value = secrets.token_urlsafe()
                conditional_check_error = True

            if conditional_check_error:
                logger.info(
                    "Generated personal access token for user GUID: %s was not "
                    "unique. Creating a new token GUID: %s", user_guid,
                    token_guid)
            # Something else happened so go back to raising the error
            else:
                raise err

            if write_attempts == max_write_attempts:
                raise err
            continue  # Try again
        # Write succeeded, break out of loop
        break

    return {
        "token_guid": token_guid,
        "token_prefix": token_prefix,
        "token_value": token_value,
        "expires": expires_timestamp
    }


def verify_token(token_hash):
    token_hash_exp_attr_values = {":token_hash": {"S": token_hash}}

    response = dynamodb.query(
        TableName=TOKEN_TABLE_NAME,
        IndexName="token_hash",
        Select="SPECIFIC_ATTRIBUTES",
        ProjectionExpression="token_guid,user_guid,expires",
        KeyConditionExpression="token_hash = :token_hash",
        ExpressionAttributeValues=token_hash_exp_attr_values)

    logger.info("DynamoDB PATCH get token by hash response: %s",
                json.dumps(response))

    items = response.get("Items")

    if not items:
        raise videon.ResourceNotFoundError

    token_entry = items[0]

    token_guid = token_entry["token_guid"]["S"]
    expires_timestamp = token_entry["expires"]["S"]

    current_datetime = datetime.datetime.utcnow().replace(microsecond=0)
    current_timestamp = current_datetime.isoformat() + "Z"

    if expires_timestamp <= current_timestamp:
        # Token has expired, so remove the hash from the table
        # Must delete both the normal entry and token hash as primary key entry
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
                "Update": {
                    "TableName": TOKEN_TABLE_NAME,
                    "Key": {
                        "token_guid": {
                            "S": token_guid
                        }
                    },
                    "UpdateExpression": "REMOVE token_hash"
                }
            },
        ],)

        logger.info(
            "Personal access token GUID %s sensitive info deleted. "
            "Expired on %s", token_guid, expires_timestamp)

        raise videon.PersonalAccessTokenError("EXPIRED")

    user_guid = token_entry["user_guid"]["S"]

    get_user_url = f"{RESTAPI_URL_PATH}users/{user_guid}"
    get_user_response = requests.get(get_user_url,
                                     headers=VIDEON_INTERNAL_HEADERS)

    if get_user_response.status_code != 200:
        raise videon.UserStatusError("USER_NOT_FOUND")

    get_user_response_json = get_user_response.json().get("user")
    assert get_user_response_json is not None

    if not get_user_response_json.get("enabled"):
        raise videon.UserStatusError("USER_DISABLED")

    if get_user_response_json.get("status") != "CONFIRMED":
        raise videon.UserStatusError("USER_NOT_CONFIRMED")

    # Update last_used timestamp to current timestamp
    last_updated_exp_attr_values = {":last_used": {"S": current_timestamp}}

    logger.info(
        "Personal access token GUID %s is valid. "
        "Updating last_used timestamp to %s.", token_guid, current_timestamp)

    dynamodb.update_item(TableName=TOKEN_TABLE_NAME,
                         Key={"token_guid": {
                             "S": token_guid
                         }},
                         UpdateExpression="SET last_used = :last_used",
                         ExpressionAttributeValues=last_updated_exp_attr_values)

    return {"user_guid": user_guid}
