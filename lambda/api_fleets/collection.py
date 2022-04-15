"""Request Handler for /fleets API Route

This is implemented as a Lambda Proxy integration.  The function is
responsible for validating the input, and sending a properly-formatted
response.  (Failure to do so will be a 5xx error for the client.)

https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
https://docs.aws.amazon.com/apigateway/latest/developerguide/handle-errors-in-lambda-integration.html
"""
import json
import logging
from os import environ
from requests.structures import CaseInsensitiveDict
from typing import Union
import uuid

# Enable X-Ray Tracing
from aws_xray_sdk.core import patch_all
import boto3

import videon_shared as videon

patch_all()

dynamodb = boto3.client("dynamodb")
dynamo_paginator_query = dynamodb.get_paginator("query")

logger = logging.getLogger()

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
    supported_methods = ("GET", "POST", "OPTIONS")
    assert event["httpMethod"] in supported_methods
    assert "Fleet" in event["requestContext"]["operationName"]

    if event["httpMethod"] == "OPTIONS":
        return videon.response_cors(", ".join(supported_methods))

    response_json = {"error_code": "UNHANDLED_CONDITION"}
    response_code = 500

    query_string_params = event.get("queryStringParameters")
    assert "headers" in event
    headers = CaseInsensitiveDict(event["headers"])

    if event.get("body") is not None:
        try:
            body = videon.convert_request_body(event["body"])
        except videon.RequestBodyError as err:
            response_json = {"message": str(err)}
            return videon.response_json(400, response_json, event)

    authorizer_user_guid = videon.get_authorizer_guid(event)
    authorizer_user_groups = videon.get_user_groups(event)
    is_org_management = bool(
        COGNITO_ORG_MANAGEMENT_GROUP_NAME in authorizer_user_groups)

    if event["httpMethod"] == "GET":
        if query_string_params is not None:
            org_guid = query_string_params.get("org_guid")
        else:
            org_guid = None
        required_permissions_level = videon.Permissions.READER
    else:
        assert body
        org_guid = body.get("org_guid")
        required_permissions_level = videon.Permissions.ADMIN

    if org_guid is None:
        org_guid = headers.get("Org-Guid")

    # Make sure user is permitted to perform action
    org_access_level = None
    if not is_org_management and not videon.is_internal_auth(event):
        try:
            org_access_level = videon.validate_user_org_access(
                authorizer_user_guid, org_guid, required_permissions_level,
                RESTAPI_URL_PATH, VIDEON_INTERNAL_HEADERS)
        except videon.PermissionsError as err:
            response_code = 403
            response_json = {"message": str(err)}
            return videon.response_json(response_code, response_json, event)
        except videon.ResourceNotFoundError:
            response_code = 404
            response_json = {
                "message": ("Organization does not exist or user is "
                            "not permitted to perform this action")
            }
            return videon.response_json(response_code, response_json, event)
    else:
        org_access_level = videon.Permissions.ADMIN

    if event["httpMethod"] == "GET":
        if query_string_params is None:
            query_string_params = {}

        fleet_name = query_string_params.get("fleet_name")
        target_user_guid = query_string_params.get("user_guid")
        pagination_token = query_string_params.get("pagination_token")
        pagination_size = query_string_params.get(
            "pagination_size", videon.PAGINATION_SIZE_DEFAULT)

        if target_user_guid is None and org_guid is None:
            target_user_guid = authorizer_user_guid

        targeting_other_user = (target_user_guid is not None and
                                target_user_guid != authorizer_user_guid)
        if targeting_other_user and not videon.is_internal_auth(event):
            response_json = {
                "message": "User does not have permission to "
                           "perform this action"
            }
            return videon.response_json(403, response_json, event)

        try:
            pagination_size = videon.validate_pagination_size(pagination_size)
        except (TypeError, ValueError) as err:
            response_json = {"message": "Invalid pagination size. " + str(err)}
            return videon.response_json(400, response_json, event)

        # user_guid is required for internal auth to pass
        if videon.is_internal_auth(event) and target_user_guid is None:
            response_json = {"message": "Missing user_guid parameter"}
            return videon.response_json(400, response_json, event)

        # Set up encryption key for pagination token
        pagination_encryption_key = videon.pagination_encryption_key(
            context.function_name, authorizer_user_guid,
            videon.is_internal_auth(event))

        try:
            pagination_token = videon.pagination_decrypt(
                pagination_token, pagination_encryption_key)

            response_json = find_fleets(target_user_guid, fleet_name, org_guid,
                                        pagination_token, pagination_size,
                                        org_access_level)

            response_json["pagination_token"] = videon.pagination_encrypt(
                response_json.get("pagination_token"),
                pagination_encryption_key)

            response_code = 200
        except videon.PaginationTokenError as err:
            response_code = 400
            response_json = {"message": "Invalid pagination token"}
    elif event["httpMethod"] == "POST":
        assert "fleet_name" in body

        if org_guid is None:
            response_json = {
                "message": ("Missing required request parameters: "
                            "[Org-Guid or org_guid]")
            }
            response_code = 400
            return videon.response_json(response_code, response_json, event)

        response_json = create_fleet(body["fleet_name"])
        add_org_to_fleet(response_json["fleet_guid"], org_guid)
        response_code = 201

    return videon.response_json(response_code, response_json, event)


def find_fleets(user_guid: Union[str, None], fleet_name: Union[str, None],
                org_guid: Union[str, None], pagination_token: Union[str, None],
                pagination_size: int, org_access_level: Union[str,
                                                              None]) -> dict:

    unfiltered_fleets = []
    if user_guid is not None:
        # Get all of the user's fleets
        unfiltered_fleets = get_fleets_by_user(user_guid)
    else:
        # Get all of that org's fleets
        unfiltered_fleets = get_fleets_by_org(org_guid, org_access_level)

    logger.info("Found fleets for user/org specified %s", unfiltered_fleets)

    if pagination_token is None:
        start_index = 0
    else:
        try:
            pagination_obj = json.loads(pagination_token)
        except json.JSONDecodeError as err:
            raise videon.PaginationTokenError from err

        if pagination_obj.get("start") is None:
            raise videon.PaginationTokenError

        start_index = pagination_obj["start"]

    # Get fleet details and filter fleets by fleet name
    found_fleets = []
    found_fleets_count = 0
    for fleet in unfiltered_fleets[start_index:]:
        fleet_guid = fleet["fleet_guid"]
        response = dynamodb.get_item(TableName=FLEETS_TABLE_NAME,
                                     Key={"fleet_guid": {
                                         "S": fleet_guid
                                     }},
                                     ConsistentRead=True)
        item = response.get("Item")
        if not item:
            logger.info("Ghost Fleet: %s", fleet_guid)
            found_fleets_count += 1
            if found_fleets_count >= pagination_size:
                break
            continue

        response_fleet_name = item["fleet_name"]["S"]

        if fleet_name is None or fleet_name in response_fleet_name:
            fleet_obj = {
                "fleet_name": response_fleet_name,
                "fleet_guid": fleet_guid
            }
            if fleet.get("access") is not None:
                fleet_obj["access"] = fleet["access"]

            found_fleets.append(fleet_obj)
            found_fleets_count += 1
            if found_fleets_count >= pagination_size:
                break

    next_index = found_fleets_count + start_index
    pagination_token = (None if len(unfiltered_fleets[next_index:]) == 0 else
                        json.dumps({"start": next_index}))

    return {"fleets": found_fleets, "pagination_token": pagination_token}


def get_fleets_by_member_guid(member_guid: str,
                              prefix: str,
                              access_level: Union[int, None] = None) -> list:
    fleets = []

    expression_values = {":member_guid": {"S": f"{prefix}{member_guid}"}}
    query_args = {
        "TableName": FLEET_ORG_USERS_TABLE_NAME,
        "IndexName": "member_guid",
        "Select": "SPECIFIC_ATTRIBUTES",
        "ProjectionExpression": "fleet_guid,access",
        "KeyConditionExpression": "member_guid = :member_guid",
        "ExpressionAttributeValues": expression_values
    }

    pagination_config = {}
    while True:
        response = dynamo_paginator_query.paginate(
            **query_args).build_full_result()

        logger.info("DynamoDB GET fleets response %s", response)

        for item in response["Items"]:
            fleet_object = {"fleet_guid": item["fleet_guid"]["S"]}
            if access_level is not None:
                fleet_object["access"] = access_level
            elif item.get("access") is not None:
                fleet_object["access"] = int(item["access"]["N"])
            fleets.append(fleet_object)

        if response.get("NextToken") is None:
            break

        pagination_config["StartingToken"] = response["NextToken"]
        query_args["PaginationConfig"] = pagination_config

    return fleets


def get_fleets_by_user(user_guid: str) -> list:
    return get_fleets_by_member_guid(user_guid, "USER#")


def get_fleets_by_org(org_guid: str,
                      access_level: Union[int, None] = None) -> list:
    return get_fleets_by_member_guid(org_guid, "ORG#", access_level)


def create_fleet(fleet_name) -> dict:
    fleet_search_key = videon.get_dynamodb_search_key(fleet_name)

    # We need to ensure GUID is unique otherwise, we will
    # overwrite an existing fleet (rare but could happen)
    # Retry once, odds that it happens twice in a row are very slim
    write_attempts = 0
    max_write_attempts = 2
    while write_attempts < max_write_attempts:
        fleet_guid = str(uuid.uuid4())
        logger.info("Creating fleet %s, %s, %s", fleet_guid, fleet_search_key,
                    fleet_name)

        try:
            dynamodb.put_item(
                TableName=FLEETS_TABLE_NAME,
                Item={
                    "fleet_guid": {
                        "S": fleet_guid
                    },
                    "fleet_search_key": {
                        "S": fleet_search_key
                    },
                    "fleet_name": {
                        "S": fleet_name
                    }
                },
                ConditionExpression="attribute_not_exists(fleet_guid)")
        except dynamodb.exceptions.ConditionalCheckFailedException as err:
            if write_attempts == max_write_attempts:
                raise err
            continue  # Try again
        break

    return {
        "message": "Fleet was created successfully.",
        "fleet_guid": fleet_guid
    }


def add_org_to_fleet(fleet_guid: str, org_guid: str) -> None:
    dynamodb.put_item(TableName=FLEET_ORG_USERS_TABLE_NAME,
                      Item={
                          "fleet_guid": {
                              "S": fleet_guid
                          },
                          "member_guid": {
                              "S": f"ORG#{org_guid}"
                          },
                      })
