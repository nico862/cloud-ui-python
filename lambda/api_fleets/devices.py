"""Request Handler for /fleets/{fleet_guid}/devices API Route

This is implemented as a Lambda Proxy integration.  The function is
responsible for validating the input, and sending a properly-formatted
response.  (Failure to do so will be a 5xx error for the client.)

https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
https://docs.aws.amazon.com/apigateway/latest/developerguide/handle-errors-in-lambda-integration.html
"""
import json
import logging
from os import environ
from typing import Union, Any

from aws_xray_sdk.core import patch_all
import boto3
import botocore.exceptions

import videon_shared as videon

# Enable X-Ray Tracing
patch_all()

logger = logging.getLogger()

dynamodb = boto3.client("dynamodb")
dynamo_paginator_query = dynamodb.get_paginator("query")

FLEET_ORG_USERS_TABLE_NAME = environ.get("FLEET_ORG_USERS_TABLE_NAME")
FLEET_DEVICES_TABLE_NAME = environ.get("FLEET_DEVICES_TABLE_NAME")

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
    supported_methods = ("GET", "POST", "DELETE", "OPTIONS")
    assert event["httpMethod"] in supported_methods
    assert "Fleet" in event["requestContext"]["operationName"]
    assert "fleet_guid" in event["pathParameters"]

    fleet_guid = event["pathParameters"]["fleet_guid"]

    # Don't need to do anything else for OPTIONS, so return
    if event["httpMethod"] == "OPTIONS":
        return videon.response_cors(", ".join(supported_methods))

    # In case a method is not handled, return this error code
    response_json = {"error_code": "UNHANDLED_CONDITION"}
    response_code = 500

    # Validate access level within fleet before proceeding
    authorizer_guid = videon.get_authorizer_guid(event)
    authorizer_user_groups = videon.get_user_groups(event)
    is_org_manager = bool(
        COGNITO_ORG_MANAGEMENT_GROUP_NAME in authorizer_user_groups)

    if event["httpMethod"] == "GET":
        required_permission_levels = videon.Permissions.READER
    else:
        required_permission_levels = videon.Permissions.ADMIN

    try:
        if not videon.is_internal_auth(event) and not is_org_manager:
            validate_user_fleet_permissions(authorizer_guid, fleet_guid,
                                            required_permission_levels)
    except videon.PermissionsError:
        response_json = {
            "message": "User does not have permissions to perform this action."
        }
        return videon.response_json(403, response_json, event)
    except videon.ResourceNotFoundError:
        response_json = {
            "message": (f"Fleet GUID {fleet_guid} does not exist, "
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

    # Handle event HTTP method
    if event["httpMethod"] == "GET":
        query_string_params = event.get("queryStringParameters")
        if query_string_params is not None:
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
            pagination_token = None
            pagination_size = videon.PAGINATION_SIZE_DEFAULT

        # Set up encryption key for pagination token
        pagination_encryption_key = videon.pagination_encryption_key(
            context.function_name, authorizer_guid,
            videon.is_internal_auth(event))

        try:
            pagination_token = videon.pagination_decrypt(
                pagination_token, pagination_encryption_key)

            response_json = get_devices(fleet_guid, pagination_token,
                                        pagination_size)

            response_json["pagination_token"] = videon.pagination_encrypt(
                response_json.get("pagination_token"),
                pagination_encryption_key)

            response_code = 200
        except videon.PaginationTokenError as err:
            response_code = 400
            response_json = {"message": "Invalid pagination token"}
    elif event["httpMethod"] == "POST":
        devices = body.get("devices", [])
        devices = list(set(devices))  # Remove duplicates
        failed_devices = add_devices(fleet_guid, devices)
        success_count = len(devices) - len(failed_devices)

        response_code = 200
        response_json = {
            "message":
                "Successfully added {} device{}".format(
                    success_count, "" if success_count == 1 else "s"),
            "failed_devices":
                failed_devices
        }
    elif event["httpMethod"] == "DELETE":
        devices = body.get("devices", [])
        devices = list(set(devices))  # Remove duplicates
        failed_devices = delete_devices(fleet_guid, devices)
        success_count = len(devices) - len(failed_devices)

        response_code = 200
        response_json = {
            "message":
                "Successfully updated {} device{}".format(
                    success_count, "" if success_count == 1 else "s"),
            "failed_devices":
                failed_devices
        }

    return videon.response_json(response_code, response_json, event)


def get_devices(fleet_guid: str, pagination_token: Union[str, None],
                pagination_size: int) -> dict:
    pagination_config = {"MaxItems": pagination_size}

    if pagination_token is not None:
        pagination_config["StartingToken"] = pagination_token

    expression_values = {":fleet_guid": {"S": fleet_guid}}

    try:
        response = dynamo_paginator_query.paginate(
            TableName=FLEET_DEVICES_TABLE_NAME,
            IndexName="fleet_guid",
            Select="SPECIFIC_ATTRIBUTES",
            ProjectionExpression="device_guid",
            KeyConditionExpression="fleet_guid = :fleet_guid",
            ExpressionAttributeValues=expression_values,
            PaginationConfig=pagination_config).build_full_result()
    except botocore.exceptions.ParamValidationError as err:
        if "ExclusiveStartKey" in str(err):
            raise videon.PaginationTokenError from err
        raise err

    output = {"devices": []}
    for item in response["Items"]:
        device_guid: str = item["device_guid"]["S"]
        output["devices"].append({"device_guid": device_guid})
    output["pagination_token"] = response.get("NextToken")

    logger.info("DynamoDB response: %s", json.dumps(response))

    return output


def add_devices(fleet_guid: str, devices: list[str]) -> list[dict[str, Any]]:
    failed_devices = []

    for device_guid in devices:
        membership_guid: str = videon.generate_membership_guid(
            fleet_guid, device_guid)

        try:
            dynamodb.put_item(
                TableName=FLEET_DEVICES_TABLE_NAME,
                Item={
                    "membership_guid": {
                        "S": membership_guid
                    },
                    "fleet_guid": {
                        "S": fleet_guid
                    },
                    "device_guid": {
                        "S": device_guid
                    }
                },
                ConditionExpression="attribute_not_exists(membership_guid)")
        except dynamodb.exceptions.ConditionalCheckFailedException:
            failed_devices.append({
                "device_guid": device_guid,
                "reason": "Device is already in fleet"
            })
            logger.info("Condition Expression Failed")
            continue

    return failed_devices


def delete_devices(fleet_guid: str, devices: list[str]) -> list[dict[str, Any]]:
    failed_devices = []

    for device_guid in devices:
        membership_guid: str = videon.generate_membership_guid(
            fleet_guid, device_guid)

        expression_values = {":device_guid": {"S": device_guid}}

        try:
            dynamodb.delete_item(
                TableName=FLEET_DEVICES_TABLE_NAME,
                Key={"membership_guid": {
                    "S": membership_guid
                }},
                ExpressionAttributeValues=expression_values,
                ConditionExpression="device_guid = :device_guid")
        except dynamodb.exceptions.ConditionalCheckFailedException:
            failed_devices.append({
                "device_guid": device_guid,
                "reason": ("Device does not exist within fleet")
            })
            logger.info("Condition Expression Failed")
            continue

    return failed_devices


# This function is duplicated in fleets/{guid}/users,
# but I want to limit calls to other lambdas and this
# lambda has direct access to the table.
# I can't add this to the shared layer without also
# passing a ton of other variables.
# If there is a better solution, please fix this.
def validate_user_fleet_permissions(user_guid: str,
                                    fleet_guid: str,
                                    required_permissions: int = None) -> int:
    if user_guid is None:
        raise videon.ResourceNotFoundError

    response = dynamodb.get_item(TableName=FLEET_ORG_USERS_TABLE_NAME,
                                 Key={
                                     "fleet_guid": {
                                         "S": fleet_guid
                                     },
                                     "member_guid": {
                                         "S": f"USER#{user_guid}"
                                     }
                                 },
                                 ProjectionExpression="access",
                                 ConsistentRead=True)

    logger.info("DynamoDB GET fleet response: %s", response)

    if "Item" not in response:
        # The user is not directly assigned to this fleet
        # Get the org that owns the fleet and return user's access in that org
        expr_attr_vals = {
            ":fleet_guid": {
                "S": fleet_guid
            },
            ":org_prefix": {
                "S": "ORG#"
            }
        }
        key_cond_expr = ("fleet_guid = :fleet_guid AND "
                         "begins_with(member_guid, :org_prefix)")

        response = dynamodb.query(TableName=FLEET_ORG_USERS_TABLE_NAME,
                                  KeyConditionExpression=key_cond_expr,
                                  ExpressionAttributeValues=expr_attr_vals)

        items = response.get("Items")
        if not items:
            raise videon.ResourceNotFoundError

        org_entry = items[0]["member_guid"]["S"]

        # Remove ORG# prefix to get guid
        org_guid = org_entry[4:]

        return videon.validate_user_org_access(user_guid, org_guid,
                                               required_permissions,
                                               RESTAPI_URL_PATH,
                                               VIDEON_INTERNAL_HEADERS)

    access_level = int(response["Item"]["access"]["N"])

    if required_permissions is not None and access_level < required_permissions:
        raise videon.PermissionsError

    return access_level
