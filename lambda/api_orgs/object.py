"""Request Handler for /orgs/{org_guid} API Route

This is implemented as a Lambda Proxy integration.  The function is
responsible for validating the input, and sending a properly-formatted
response.  (Failure to do so will be a 5xx error for the client.)

https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
https://docs.aws.amazon.com/apigateway/latest/developerguide/handle-errors-in-lambda-integration.html
"""

import boto3
import json
import logging
import videon_shared as videon

from os import environ

# Enable X-Ray Tracing
from aws_xray_sdk.core import patch_all

patch_all()

dynamodb = boto3.client("dynamodb")
dynamodb_resource = boto3.resource("dynamodb")
logger = logging.getLogger()

ORGANIZATIONS_TABLE_NAME = environ.get("ORGANIZATIONS_TABLE_NAME")
ORG_USERS_TABLE_NAME = environ.get("ORG_USERS_TABLE_NAME")


def lambda_handler(event, context):  # pylint: disable=unused-argument

    videon.setup_logging(logging.INFO, event)

    # If this fails the API gateway is misconfigured
    supported_methods = ("DELETE", "GET", "PATCH", "OPTIONS")
    assert event["httpMethod"] in supported_methods
    assert "Organization" in event["requestContext"]["operationName"]

    org_guid = event["pathParameters"]["org_guid"]

    if event["httpMethod"] == "OPTIONS":
        return videon.response_cors(", ".join(supported_methods))

    if event.get("body") is not None:
        try:
            body = videon.convert_request_body(event["body"])
        except videon.RequestBodyError as err:
            response_json = {"message": str(err)}
            response_code = 400
            return videon.response_json(response_code, response_json, event)

    try:
        if event["httpMethod"] == "GET":
            response_json = get_organization(org_guid)
        elif event["httpMethod"] == "PATCH":
            response_json = update_organization(org_guid, body)
        elif event["httpMethod"] == "DELETE":
            response_json = delete_organization(org_guid, body["reason"])
        response_code = 200
    except (videon.ResourceNotFoundError, ValueError) as err:
        response_code = 404
        response_json = {"message": str(err)}

    return videon.response_json(response_code, response_json, event)


def get_organization(org_guid):
    response = dynamodb.get_item(TableName=ORGANIZATIONS_TABLE_NAME,
                                 Key={"org_guid": {
                                     "S": org_guid
                                 }},
                                 ConsistentRead=True)

    logger.info("DynamoDB response: %s", json.dumps(response))

    if "Item" not in response:
        raise ValueError(f"Organization GUID {org_guid} does not exist," \
                            " or you do not have permission to access it.")

    return {"org": {"org_name": response["Item"]["org_name"]["S"]}}


def update_organization(org_guid, changes):
    # Currently, we're not doing actual mapping, but
    # we will be able to in the future
    attribute_map = {"org_name": "org_name"}

    logger.info(changes)

    updates = {}
    for key, value in changes.items():
        attribute_key = attribute_map.get(key)
        if attribute_key is not None:
            updates[attribute_key] = value

    if "org_name" in updates:
        org_search_key = videon.get_dynamodb_search_key(updates["org_name"])
        updates["org_search_key"] = org_search_key

    logger.info(updates)

    if not updates:
        return {
            "message": ("Organization updated successfully "
                        "(received empty request body)")
        }

    # This goes through all the keys and values in updates,
    # and converts them into a string in the format of
    # SET key0=:value0, key1=:value1, etc...

    # pylint: disable=line-too-long
    update_expression = f"SET { ', '.join([ '{}={}'.format(key, ':value' + str(i)) for i, key in enumerate(updates.keys()) ] ) }"
    # pylint: enable=line-too-long

    # This fills in the values, it allows for support of spaces in org_name
    expression_values = {
        ":value" + str(i): {
            "S": value
        } for i, value in enumerate(updates.values())
    }
    # Make the org_guid available to ConditionExpression
    expression_values[":org_guid"] = {"S": org_guid}
    try:
        dynamodb.update_item(TableName=ORGANIZATIONS_TABLE_NAME,
                             Key={"org_guid": {
                                 "S": org_guid
                             }},
                             UpdateExpression=update_expression,
                             ExpressionAttributeValues=expression_values,
                             ConditionExpression="org_guid = :org_guid")
    except dynamodb.exceptions.ConditionalCheckFailedException as err:
        raise videon.ResourceNotFoundError("Organization not found") from err

    return {"message": "Organization updated successfully"}


def delete_organization(org_guid, reason):
    try:
        dynamodb.delete_item(
            TableName=ORGANIZATIONS_TABLE_NAME,
            Key={"org_guid": {
                "S": org_guid
            }},
            ExpressionAttributeValues={":org_guid": {
                "S": org_guid
            }},
            ConditionExpression="org_guid = :org_guid")
    except dynamodb.exceptions.ConditionalCheckFailedException as err:
        raise videon.ResourceNotFoundError("Organization not found") from err

    logger.info("Organization %s deleted. Reason: %s", org_guid, reason)

    # Also delete any memberships for that org
    org_guid_exp_attr_values = {":org_guid": {"S": org_guid}}
    get_response = dynamodb.query(
        TableName=ORG_USERS_TABLE_NAME,
        IndexName="org_guid",
        Select="SPECIFIC_ATTRIBUTES",
        ProjectionExpression="membership_guid",
        KeyConditionExpression="org_guid = :org_guid",
        ExpressionAttributeValues=org_guid_exp_attr_values)

    items = get_response.get("Items")

    table = dynamodb_resource.Table(ORG_USERS_TABLE_NAME)
    with table.batch_writer() as batch:
        for item in items:
            membership_guid = item["membership_guid"]["S"]
            batch.delete_item(Key={"membership_guid": membership_guid})

    return {"message": "Organization successfully deleted"}
