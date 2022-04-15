"""Request Handler for /fleets/{fleet_guid}/users API Route

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

FLEETS_TABLE_NAME = environ.get("FLEETS_TABLE_NAME")
FLEET_ORG_USERS_TABLE_NAME = environ.get("FLEET_ORG_USERS_TABLE_NAME")

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
    supported_methods = ("GET", "POST", "PUT", "DELETE", "OPTIONS")
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

    user_access = None
    try:
        if not videon.is_internal_auth(event) and not is_org_manager:
            user_access = validate_user_fleet_permissions(
                authorizer_guid, fleet_guid, required_permission_levels)
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
        # Initialize parameters
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

            response_json = find_users(fleet_guid, target_user_guid,
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
            exists_response = requests.get(
                f"{RESTAPI_URL_PATH}users/{user_guid}",
                headers=VIDEON_INTERNAL_HEADERS)

        if user_guid is None or exists_response.status_code != 200:
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
            response_json = join_fleet(fleet_guid, user_guid, access)
        except videon.ResourceExistsError as err:
            response_code = 409
            response_json = {"message": str(err)}
    elif event["httpMethod"] == "PUT":
        users = body.get("users", [])
        failed_users = update_users(fleet_guid, users)
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
        failed_users = delete_users(fleet_guid, users)
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


def find_users(fleet_guid: str, user_guid: str, pagination_token: Union[str,
                                                                        None],
               pagination_size: int) -> dict:
    if user_guid is not None:
        try:
            access = validate_user_fleet_permissions(user_guid, fleet_guid)
            response_json = {
                "users": [{
                    "user_guid": user_guid,
                    "access": access
                }]
            }
        except videon.ResourceNotFoundError:
            response_json = {"users": []}
        return response_json

    member_pagination_token = None
    if pagination_token is not None:
        pagination_token_obj = json.loads(pagination_token)
        # Decode pagination token object
        # u: true if we stopped while we were paginating users
        # t: token from the last page
        paginating_users = pagination_token_obj["u"]
        member_pagination_token = pagination_token_obj["t"]

    output = {"users": []}
    # Get all fleet users first
    if pagination_token is None or paginating_users:
        expression_values = {
            ":fleet_guid": {
                "S": fleet_guid
            },
            ":user_prefix": {
                "S": "USER#"
            }
        }
        key_cond_expr = ("fleet_guid = :fleet_guid AND "
                         "begins_with(member_guid, :user_prefix)")

        pagination_config = {"MaxItems": pagination_size}

        if member_pagination_token is not None:
            pagination_config["StartingToken"] = member_pagination_token

        try:
            response = dynamo_paginator_query.paginate(
                TableName=FLEET_ORG_USERS_TABLE_NAME,
                Select="SPECIFIC_ATTRIBUTES",
                ProjectionExpression="member_guid,access",
                KeyConditionExpression=key_cond_expr,
                ExpressionAttributeValues=expression_values,
                PaginationConfig=pagination_config).build_full_result()
        except botocore.exceptions.ParamValidationError as err:
            # "Invalid type for parameter ExclusiveStartKey" in the error
            # message means that the pagination token was invalid
            if "ExclusiveStartKey" in str(err):
                raise videon.PaginationTokenError from err
            raise err

        logger.info("DynamoDB GET fleet users response: %s", response)

        for item in response["Items"]:
            item_guid: str = item["member_guid"]["S"]
            # Remove USER# prefix
            user_guid = item_guid[5:]
            access = int(item["access"]["N"])
            output["users"].append({"user_guid": user_guid, "access": access})

        # Create pagination object to keep track of where we are
        if response.get("NextToken") is not None:
            output_pagination_obj = json.dumps({
                "u": True,
                "t": response.get("NextToken")
            })
            output["pagination_token"] = output_pagination_obj
            return output

    # Now get the fleet's org and the users that are in the organization
    org_guid = get_fleet_org(fleet_guid)

    # Fleet doesn't have an org, so we're done
    if org_guid is None:
        return output

    remaining_page_size = pagination_size - len(output["users"])

    # If we are at the pagination size limit already,
    # check to see if there are any more results to paginate,
    # so pagination token can be set accordingly
    payload = {"user_guid": user_guid}
    if remaining_page_size == 0:
        payload["pagination_size"] = 1
    else:
        payload["pagination_size"] = remaining_page_size
        if member_pagination_token is not None:
            payload["pagination_token"] = member_pagination_token

    response = requests.get(f"{RESTAPI_URL_PATH}orgs/{org_guid}/users",
                            headers=VIDEON_INTERNAL_HEADERS,
                            params=payload)
    assert response.status_code == 200

    org_users = response.json()["users"]
    org_users_pagination_token = response.json().get("pagination_token")

    # Already at pagination size, set token accordingly
    # Or no users in this org, so we're done
    if remaining_page_size == 0 or not org_users:
        if org_users:
            output_pagination_obj = json.dumps({"u": False, "t": None})
            output["pagination_token"] = output_pagination_obj

        return output

    # Add the org guid to the user so we know
    # that they are attached via an org
    for user in org_users:
        user["org_guid"] = org_guid

    output["users"].extend(org_users)

    if org_users_pagination_token is not None:
        output_pagination_obj = json.dumps({
            "u": False,
            "t": org_users_pagination_token
        })
        output["pagination_token"] = output_pagination_obj

    return output


def join_fleet(fleet_guid: str, user_guid: str, access: int) -> dict:
    # Check if user is in the org that owns the fleet before adding
    org_guid = get_fleet_org(fleet_guid)
    try:
        videon.validate_user_org_access(user_guid, org_guid, None,
                                        RESTAPI_URL_PATH,
                                        VIDEON_INTERNAL_HEADERS)
        # If we get here, the user is in the org that owns the fleet
        raise videon.ResourceExistsError(
            "User already in organization that owns fleet")
    except videon.ResourceNotFoundError:
        pass  # User was not found so we can add them

    try:
        dynamodb.put_item(
            TableName=FLEET_ORG_USERS_TABLE_NAME,
            Item={
                "fleet_guid": {
                    "S": fleet_guid
                },
                "member_guid": {
                    "S": f"USER#{user_guid}"
                },
                "access": {
                    "N": str(access)
                }
            },
            ConditionExpression="attribute_not_exists(fleet_guid)")
    except dynamodb.exceptions.ConditionalCheckFailedException as err:
        raise videon.ResourceExistsError("User already in fleet") from err

    return {"message": "Fleet joined successfully"}


def update_users(fleet_guid: str,
                 users: list[dict[str, Any]]) -> list[dict[str, Any]]:
    failed_users = []

    update_expression = "SET access = :access"

    for user in users:
        user_guid = user["user_guid"]
        access = user["access"]

        if access not in videon.Permissions:
            failed_users.append({
                "user_guid": user_guid,
                "reason": "Invalid access level given"
            })
            continue

        member_guid = f"USER#{user_guid}"
        expression_values = {
            ":access": {
                "N": str(access)
            },
            ":member_guid": {
                "S": member_guid
            }
        }

        try:
            dynamodb.update_item(
                TableName=FLEET_ORG_USERS_TABLE_NAME,
                Key={
                    "fleet_guid": {
                        "S": fleet_guid
                    },
                    "member_guid": {
                        "S": member_guid
                    }
                },
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_values,
                ConditionExpression="member_guid = :member_guid")
        except dynamodb.exceptions.ConditionalCheckFailedException:
            failed_users.append({
                "user_guid":
                    user_guid,
                "reason": ("User does not exist within fleet or "
                           "exists in fleet via fleet's organization")
            })
            logger.info("Condition Expression Failed")
            continue

    return failed_users


def delete_users(fleet_guid: str, users: list[str]) -> list[dict[str, Any]]:
    failed_users = []

    for user in users:
        member_guid = f"USER#{user}"
        expression_values = {":member_guid": {"S": member_guid}}

        try:
            dynamodb.delete_item(
                TableName=FLEET_ORG_USERS_TABLE_NAME,
                Key={
                    "fleet_guid": {
                        "S": fleet_guid
                    },
                    "member_guid": {
                        "S": member_guid
                    }
                },
                ExpressionAttributeValues=expression_values,
                ConditionExpression="member_guid = :member_guid")
        except dynamodb.exceptions.ConditionalCheckFailedException:
            failed_users.append({
                "user_guid":
                    user,
                "reason": ("User does not exist within fleet or "
                           "exists in fleet via fleet's organization")
            })
            logger.info("Condition Expression Failed")
            continue

    return failed_users


# This function is duplicated in fleets/{guid}/devices,
# but I want to limit calls to other lambdas, and
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


def get_fleet_org(fleet_guid: str) -> Union[str, None]:
    expression_values = {
        ":fleet_guid": {
            "S": fleet_guid
        },
        ":org_prefix": {
            "S": "ORG#"
        }
    }
    key_cond_expr = ("fleet_guid = :fleet_guid AND "
                     "begins_with(member_guid, :org_prefix)")

    org_response = dynamo_paginator_query.paginate(
        TableName=FLEET_ORG_USERS_TABLE_NAME,
        Select="SPECIFIC_ATTRIBUTES",
        ProjectionExpression="member_guid",
        KeyConditionExpression=key_cond_expr,
        ExpressionAttributeValues=expression_values).build_full_result()

    logger.info("DynamoDB GET fleet org response: %s", org_response)

    org = org_response.get("Items")

    if not org:
        return None

    org_entry = org[0]["member_guid"]["S"]
    org_guid = org_entry[4:]
    return org_guid
