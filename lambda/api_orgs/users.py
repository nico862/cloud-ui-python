"""Request Handler for /orgs/{org_guid}/users API Route

This is implemented as a Lambda Proxy integration.  The function is
responsible for validating the input, and sending a properly-formatted
response.  (Failure to do so will be a 5xx error for the client.)

https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
https://docs.aws.amazon.com/apigateway/latest/developerguide/handle-errors-in-lambda-integration.html
"""
import boto3
import botocore.exceptions
import requests
import json
import logging
import videon_shared as videon

from typing import Union, Any

# Enable X-Ray Tracing
from aws_xray_sdk.core import patch_all
from os import environ

patch_all()

RESTAPI_URL_PATH = environ.get("RESTAPI_URL_PATH")
ORG_USERS_TABLE_NAME = environ.get("ORG_USERS_TABLE_NAME")

COGNITO_ORG_MANAGEMENT_GROUP_NAME = environ.get(
    "COGNITO_ORG_MANAGEMENT_GROUP_NAME")

dynamodb = boto3.client("dynamodb")
dynamo_paginator_query = dynamodb.get_paginator("query")

secret_manager = boto3.client("secretsmanager")
VIDEON_INTERNAL_AUTH_SECRET: str = secret_manager.get_secret_value(
    SecretId=environ["VIDEON_INTERNAL_AUTH_ARN"])["SecretString"]
VIDEON_INTERNAL_HEADERS = {
    "Authorization": "VIDEON_INTERNAL_AUTH " + VIDEON_INTERNAL_AUTH_SECRET
}

logger = logging.getLogger()


def lambda_handler(event, context) -> dict:  # pylint: disable=unused-argument

    videon.setup_logging(logging.INFO, event)

    # Basic sanity checks (things that should never happen)
    # If these fail the API Gateway is probably misconfigured
    supported_methods = ("GET", "POST", "PUT", "DELETE", "OPTIONS")
    assert event["httpMethod"] in supported_methods
    assert "Organization" in event["requestContext"]["operationName"]
    assert "org_guid" in event["pathParameters"]

    org_guid = event["pathParameters"]["org_guid"]

    if event["httpMethod"] == "OPTIONS":
        return videon.response_cors(", ".join(supported_methods))

    # Validate access level within org before proceeding
    authorizer_guid = videon.get_authorizer_guid(event)
    authorizer_user_groups = videon.get_user_groups(event)
    is_org_manager = bool(
        COGNITO_ORG_MANAGEMENT_GROUP_NAME in authorizer_user_groups)

    if event["httpMethod"] == "GET":
        required_permission_levels = videon.Permissions.READER
    else:
        required_permission_levels = videon.Permissions.ADMIN

    user_access = None
    try:
        if not videon.is_internal_auth(event) and not is_org_manager:
            user_access = validate_user_org_permissions(
                authorizer_guid, org_guid, required_permission_levels)
    except videon.PermissionsError:
        response_json = {
            "message": "User does not have permissions to perform this action."
        }
        return videon.response_json(403, response_json, event)
    except videon.ResourceNotFoundError:
        response_json = {
            "message": (f"Organization GUID {org_guid} does not exist, "
                        "or you do not have permission to access it.")
        }
        return videon.response_json(404, response_json, event)

    # Validate request body
    if event.get("body") is not None:
        try:
            body = videon.convert_request_body(event["body"])
        except videon.RequestBodyError as err:
            response_json = {"message": str(err)}
            return videon.response_json(400, response_json, event)

    if event["httpMethod"] == "GET":
        query_string_params = event.get("queryStringParameters")
        if query_string_params is not None:
            pagination_token = query_string_params.get("pagination_token")
            pagination_size = query_string_params.get("pagination_size")
            target_user_guid = query_string_params.get("user_guid")

            try:
                pagination_size = videon.validate_pagination_size(
                    pagination_size)
            except (TypeError, ValueError) as err:
                response_json = {
                    "message": "Invalid pagination size. " + str(err)
                }
                return videon.response_json(400, response_json, event)

            if target_user_guid == authorizer_guid and user_access is not None:
                # We already have the current user's access
                response_json = {
                    "users": [{
                        "user_guid": authorizer_guid,
                        "access": user_access
                    }]
                }
                response_code = 200
                return videon.response_json(response_code, response_json, event)

        else:
            pagination_token = None
            pagination_size = videon.PAGINATION_SIZE_DEFAULT
            target_user_guid = None

        # Set up encryption key for pagination token
        encryption_guid = target_user_guid or authorizer_guid
        pagination_encryption_key = videon.pagination_encryption_key(
            context.function_name, encryption_guid,
            videon.is_internal_auth(event))

        try:
            pagination_token = videon.pagination_decrypt(
                pagination_token, pagination_encryption_key)

            response_json = find_users(org_guid, target_user_guid,
                                       pagination_token, pagination_size)

            response_json["pagination_token"] = videon.pagination_encrypt(
                response_json.get("pagination_token"),
                pagination_encryption_key)

            response_code = 200
        except videon.PaginationTokenError as err:
            response_code = 400
            response_json = {"message": "Invalid pagination token"}
    elif event["httpMethod"] == "POST":
        user_guid = body.get("user_guid")

        try:
            access = videon.validate_numeric_param_value(body["access"],
                                                         integer=True)
            assert access in videon.Permissions
        except (TypeError, ValueError, AssertionError) as err:
            response_json = {"message": "Invalid access level. " + str(err)}
            return videon.response_json(400, response_json, event)

        if user_guid is not None:
            exists_req = requests.get(f"{RESTAPI_URL_PATH}users/{user_guid}",
                                      headers=VIDEON_INTERNAL_HEADERS)

        if user_guid is None or exists_req.status_code != 200:
            create_response = requests.post(f"{RESTAPI_URL_PATH}users",
                                            data=event["body"],
                                            headers=VIDEON_INTERNAL_HEADERS)

            if create_response.status_code != 201:
                response_json = {
                    "message": create_response.json().get("message")
                }
                return videon.response_json(create_response.status_code,
                                            response_json, event)

            user_guid = create_response.json()["user_guid"]
            response_code = 201
        else:
            response_code = 200

        try:
            response_json = join_organization(org_guid, user_guid, access)
        except videon.ResourceExistsError:
            response_code = 409
            response_json = {"message": "User is already in organization"}
    elif event["httpMethod"] == "PUT":
        users = body.get("users", [])
        failed_users = update_users(org_guid, users)
        success_count = len(users) - len(failed_users)

        response_code = 200
        response_json = {
            "message":
                "Successfully updated {} user{}".format(
                    success_count, "" if success_count == 1 else "s"),
            "failed_users":
                failed_users
        }
    elif event["httpMethod"] == "DELETE":
        users = body.get("users", [])
        users = list(set(users))  # Remove duplicates
        failed_users = delete_users(org_guid, users)
        success_count = len(users) - len(failed_users)

        response_code = 200
        response_json = {
            "message":
                "Successfully updated {} user{}".format(
                    success_count, "" if success_count == 1 else "s"),
            "failed_users":
                failed_users
        }

    return videon.response_json(response_code, response_json, event)


def find_users(org_guid: str,
               user_guid: str,
               pagination_token: Union[str, None] = None,
               pagination_size: int = videon.PAGINATION_SIZE_DEFAULT) -> dict:
    if user_guid is not None:
        try:
            access = validate_user_org_permissions(user_guid, org_guid)
            response_json = {
                "users": [{
                    "user_guid": user_guid,
                    "access": access
                }]
            }
        except videon.ResourceNotFoundError:
            response_json = {"users": []}
        return response_json

    pagination_config = {"MaxItems": pagination_size}

    if pagination_token is not None:
        pagination_config["StartingToken"] = pagination_token

    expression_values = {":org_guid": {"S": org_guid}}

    try:
        response = dynamo_paginator_query.paginate(
            TableName=ORG_USERS_TABLE_NAME,
            IndexName="org_guid",
            Select="SPECIFIC_ATTRIBUTES",
            ProjectionExpression="user_guid,access",
            KeyConditionExpression="org_guid = :org_guid",
            ExpressionAttributeValues=expression_values,
            PaginationConfig=pagination_config).build_full_result()
    except botocore.exceptions.ParamValidationError as err:
        if "ExclusiveStartKey" in str(err):
            raise videon.PaginationTokenError from err
        raise err

    output = {"users": []}
    for item in response["Items"]:
        item_guid: str = item["user_guid"]["S"]
        item_access: int = int(item["access"]["N"])

        output["users"].append({"user_guid": item_guid, "access": item_access})
    output["pagination_token"] = response.get("NextToken")

    logger.info("DynamoDB response: %s", json.dumps(response))

    return output


def join_organization(org_guid: str, user_guid: str, access: int) -> dict:
    membership_guid = videon.generate_membership_guid(org_guid, user_guid)

    logger.info("User %s joining organization %s", user_guid, org_guid)

    try:
        dynamodb.put_item(
            TableName=ORG_USERS_TABLE_NAME,
            Item={
                "membership_guid": {
                    "S": membership_guid
                },
                "org_guid": {
                    "S": org_guid
                },
                "user_guid": {
                    "S": user_guid
                },
                "access": {
                    "N": str(access)
                }
            },
            ConditionExpression="attribute_not_exists(membership_guid)")
    except dynamodb.exceptions.ConditionalCheckFailedException as err:
        raise videon.ResourceExistsError from err

    return {"message": "Organization joined successfully"}


def update_users(org_guid: str, users: list[dict[str,
                                                 Any]]) -> list[dict[str, Any]]:
    failed_users = []

    update_expression = "SET access = :access"

    for user in users:
        user_guid = user["user_guid"]
        access = user["access"]
        membership_guid: str = videon.generate_membership_guid(
            org_guid, user_guid)

        if access not in videon.Permissions:
            failed_users.append({
                "user_guid": user_guid,
                "reason": "Invalid access level given"
            })
            continue

        logger.info("User: %s Perm: %i", user_guid, access)
        expression_values = {
            ":access": {
                "N": str(access)
            },
            ":user_guid": {
                "S": user_guid
            }
        }

        try:
            dynamodb.update_item(
                TableName=ORG_USERS_TABLE_NAME,
                Key={"membership_guid": {
                    "S": membership_guid
                }},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_values,
                ConditionExpression="user_guid = :user_guid")
        except dynamodb.exceptions.ConditionalCheckFailedException:
            failed_users.append({
                "user_guid": user_guid,
                "reason": ("User does not exist within organization")
            })
            logger.info("Condition Expression Failed")
            continue

    return failed_users


def delete_users(org_guid: str, users: list[str]) -> list[dict[str, Any]]:
    failed_users = []

    for user in users:
        membership_guid: str = videon.generate_membership_guid(org_guid, user)

        expression_values = {":user_guid": {"S": user}}

        try:
            dynamodb.delete_item(
                TableName=ORG_USERS_TABLE_NAME,
                Key={"membership_guid": {
                    "S": membership_guid
                }},
                ExpressionAttributeValues=expression_values,
                ConditionExpression="user_guid = :user_guid")
        except dynamodb.exceptions.ConditionalCheckFailedException:
            failed_users.append({
                "user_guid": user,
                "reason": ("User does not exist within organization")
            })
            logger.info("Condition Expression Failed")
            continue

    return failed_users


# Given a user_guid and org_guid return the access level in the Organization
def validate_user_org_permissions(user_guid: str,
                                  org_guid: str,
                                  required_permissions: int = None) -> int:
    if user_guid is None:
        raise videon.ResourceNotFoundError

    membership_guid: str = videon.generate_membership_guid(org_guid, user_guid)

    response = dynamodb.get_item(
        TableName=ORG_USERS_TABLE_NAME,
        Key={"membership_guid": {
            "S": membership_guid
        }},
        ProjectionExpression="access",
        ConsistentRead=True)

    logger.info(response)

    if "Item" not in response:
        raise videon.ResourceNotFoundError

    access_level = int(response["Item"]["access"]["N"])

    if required_permissions is not None and access_level < required_permissions:
        raise videon.PermissionsError

    return access_level
