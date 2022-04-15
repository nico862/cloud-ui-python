"""Request Handler for /fleets/{fleet_guid} API Route

This is implemented as a Lambda Proxy integration.  The function is
responsible for validating the input, and sending a properly-formatted
response.  (Failure to do so will be a 5xx error for the client.)

https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
https://docs.aws.amazon.com/apigateway/latest/developerguide/handle-errors-in-lambda-integration.html
"""
import json
import logging
from os import environ

# Enable X-Ray Tracing
from aws_xray_sdk.core import patch_all
import boto3

import videon_shared as videon

patch_all()

dynamodb = boto3.client("dynamodb")
dynamodb_resource = boto3.resource("dynamodb")

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
    supported_methods = ("GET", "PATCH", "DELETE", "OPTIONS")
    assert event["httpMethod"] in supported_methods
    assert "Fleet" in event["requestContext"]["operationName"]

    fleet_guid = event["pathParameters"]["fleet_guid"]

    if event["httpMethod"] == "OPTIONS":
        return videon.response_cors(", ".join(supported_methods))

    response_json = {"error_code": "UNHANDLED_CONDITION"}
    response_code = 500

    if event.get("body") is not None:
        try:
            body = videon.convert_request_body(event["body"])
        except videon.RequestBodyError as err:
            response_json = {"message": str(err)}
            return videon.response_json(400, response_json, event)

    # Validate user has appropriate permission level
    authorizer_user_guid = videon.get_authorizer_guid(event)
    authorizer_user_groups = videon.get_user_groups(event)

    is_org_manager = bool(
        COGNITO_ORG_MANAGEMENT_GROUP_NAME in authorizer_user_groups)

    if event["httpMethod"] == "GET":
        required_permission_levels = videon.Permissions.READER
    else:
        required_permission_levels = videon.Permissions.ADMIN

    if not videon.is_internal_auth(event) and not is_org_manager:
        try:
            videon.validate_user_fleet_access(authorizer_user_guid, fleet_guid,
                                              required_permission_levels,
                                              RESTAPI_URL_PATH,
                                              VIDEON_INTERNAL_HEADERS)
        except videon.PermissionsError as err:
            response_code = 403
            response_json = {"message": str(err)}
            return videon.response_json(response_code, response_json, event)
        except videon.ResourceNotFoundError:
            response_code = 404
            response_json = {
                "message": (f"Fleet GUID {fleet_guid} does not exist,"
                            " or you do not have permission to access it.")
            }
            return videon.response_json(response_code, response_json, event)

    try:
        if event["httpMethod"] == "GET":
            response_json = get_fleet(fleet_guid)
        elif event["httpMethod"] == "PATCH":
            response_json = update_fleet(fleet_guid, body)
        elif event["httpMethod"] == "DELETE":
            response_json = delete_fleet(fleet_guid, body["reason"])
        response_code = 200
    except videon.ResourceNotFoundError as err:
        response_code = 404
        response_json = {"message": str(err)}

    return videon.response_json(response_code, response_json, event)


def get_fleet(fleet_guid: str) -> dict:
    response = dynamodb.get_item(TableName=FLEETS_TABLE_NAME,
                                 Key={"fleet_guid": {
                                     "S": fleet_guid
                                 }},
                                 ConsistentRead=True)

    logger.info("DynamoDB response: %s", json.dumps(response))

    if "Item" not in response:
        raise videon.ResourceNotFoundError("Fleet not found")

    return {"fleet": {"fleet_name": response["Item"]["fleet_name"]["S"]}}


def update_fleet(fleet_guid, changes):
    # Map of request body-to-DB column names
    attribute_map = {"fleet_name": "fleet_name"}

    updates = {}
    for key, value in changes.items():
        attribute_key = attribute_map.get(key)
        if attribute_key is not None:
            updates[attribute_key] = value

    if "fleet_name" in updates:
        fleet_search_key = videon.get_dynamodb_search_key(updates["fleet_name"])
        updates["fleet_search_key"] = fleet_search_key

    logger.info("Request changes: %s, actual changes: %s", changes, updates)

    if not updates:
        return {
            "message": ("Fleet updated successfully "
                        "(received empty request body)")
        }

    # Convert updates into a string in the format of
    # SET keyname1 = :keyname1, keyname2 = :keyname2, ..., keynameN =: keynameN
    key_name_assignments = ", ".join(
        "{}={}".format(key, " :" + key) for key in updates)
    update_expression = f"SET {key_name_assignments}"

    # Substitute values for value variable names
    # FIXME: this assumes every value is a string, if non-string values
    # are added to the table this MUST be fixed
    expression_values = {}
    for key, value in updates.items():
        expression_values[":" + key] = {"S": value}

    expression_values[":fleet_guid"] = {"S": fleet_guid}
    try:
        dynamodb.update_item(TableName=FLEETS_TABLE_NAME,
                             Key={"fleet_guid": {
                                 "S": fleet_guid
                             }},
                             UpdateExpression=update_expression,
                             ExpressionAttributeValues=expression_values,
                             ConditionExpression="fleet_guid = :fleet_guid")
    except dynamodb.exceptions.ConditionalCheckFailedException as err:
        raise videon.ResourceNotFoundError("Fleet not found") from err

    return {"message": "Fleet updated successfully"}


def delete_fleet(fleet_guid, reason):
    fleet_guid_exp_attr_values = {":fleet_guid": {"S": fleet_guid}}

    try:
        dynamodb.delete_item(
            TableName=FLEETS_TABLE_NAME,
            Key={"fleet_guid": {
                "S": fleet_guid
            }},
            ExpressionAttributeValues=fleet_guid_exp_attr_values,
            ConditionExpression="fleet_guid = :fleet_guid")
    except dynamodb.exceptions.ConditionalCheckFailedException as err:
        raise videon.ResourceNotFoundError("Fleet not found") from err

    logger.info("Fleet %s deleted. Reason: %s", fleet_guid, reason)

    # Also delete any memberships for that fleet
    get_response = dynamodb.query(
        TableName=FLEET_ORG_USERS_TABLE_NAME,
        KeyConditionExpression="fleet_guid = :fleet_guid",
        ExpressionAttributeValues=fleet_guid_exp_attr_values)

    items = get_response.get("Items")

    table = dynamodb_resource.Table(FLEET_ORG_USERS_TABLE_NAME)
    with table.batch_writer() as batch:
        for item in items:
            member_guid = item["member_guid"]["S"]
            batch.delete_item(Key={
                "fleet_guid": fleet_guid,
                "member_guid": member_guid
            })

    return {"message": "Fleet successfully deleted"}
