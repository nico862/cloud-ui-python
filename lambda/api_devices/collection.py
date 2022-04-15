"""Request Handler for /devices API Route

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

# Enable X-Ray Tracing
from aws_xray_sdk.core import patch_all
import boto3
import botocore.exceptions

import videon_shared as videon

patch_all()

logger = logging.getLogger()

dynamodb = boto3.client("dynamodb")
dynamo_paginator_query = dynamodb.get_paginator("query")
iot = boto3.client("iot")

DEVICE_ORG_TABLE_NAME = environ.get("DEVICE_ORG_TABLE_NAME")


def lambda_handler(event, context):  # pylint: disable=unused-argument

    videon.setup_logging(logging.INFO, event)

    # Basic sanity checks (things that should never happen)
    # If these fail the API Gateway is probably misconfigured
    supported_methods = ("GET", "OPTIONS")
    assert event["httpMethod"] in supported_methods
    assert "Devices" in event["requestContext"]["operationName"]

    if event["httpMethod"] == "OPTIONS":
        return videon.response_cors(", ".join(supported_methods))

    response_json = {"error_code": "UNHANDLED_CONDITION"}
    response_code = 500

    if event["httpMethod"] == "GET":
        query_string_params = event.get("queryStringParameters", {})
        if query_string_params is None:
            query_string_params = {}

        pagination_token = query_string_params.get("pagination_token")
        pagination_size = query_string_params.get("pagination_size")
        org_guid = query_string_params.get("org_guid")

        try:
            pagination_size = videon.validate_pagination_size(pagination_size)
        except (TypeError, ValueError) as err:
            response_json = {"message": "Invalid pagination size. " + str(err)}
            response_code = 400
            return videon.response_json(response_code, response_json, event)

        assert "headers" in event
        headers = CaseInsensitiveDict(event["headers"])
        if headers is not None and org_guid is None:
            org_guid = headers.get("Org-Guid")

        if org_guid is None:
            response_json = {
                "message": "Missing required request parameters: " \
                           "[Org-Guid or org_guid]"
            }
            response_code = 400
            return videon.response_json(response_code, response_json, event)

        # TODO: check if user has permissions for this action
        # e.g. they are in the specified org, or appropriate cognito group,
        #      or internal auth

        # Set up encryption key for pagination token
        pagination_encryption_key = videon.pagination_encryption_key(
            context.function_name, videon.get_authorizer_guid(event),
            videon.is_internal_auth(event))

        try:
            decrypted_pagination_token = videon.pagination_decrypt(
                pagination_token, pagination_encryption_key)

            response_json = get_devices(org_guid, pagination_size,
                                        decrypted_pagination_token)

            response_json["pagination_token"] = videon.pagination_encrypt(
                response_json.get("pagination_token"),
                pagination_encryption_key)

            response_code = 200
        except videon.PaginationTokenError:
            response_code = 400
            response_json = {"message": "Invalid pagination token"}

    return videon.response_json(response_code, response_json, event)


def get_devices(org_guid, pagination_size, pagination_token):
    pagination_config = {}
    pagination_config["MaxItems"] = pagination_size
    if pagination_token is not None:
        pagination_config["StartingToken"] = pagination_token

    org_guid_exp_attr_values = {":org_guid": {"S": org_guid}}

    try:
        query_response = dynamo_paginator_query.paginate(
            TableName=DEVICE_ORG_TABLE_NAME,
            IndexName="org_guid",
            KeyConditionExpression="org_guid = :org_guid",
            ExpressionAttributeValues=org_guid_exp_attr_values,
            PaginationConfig=pagination_config).build_full_result()
    except botocore.exceptions.ParamValidationError as err:
        # "Invalid type for parameter ExclusiveStartKey" in the error message
        # means that the pagination token was invalid
        if "ExclusiveStartKey" in str(err):
            raise videon.PaginationTokenError from err
        raise err

    logger.info("DynamoDB GET devices by org response: %s",
                json.dumps(query_response))

    devices = {"devices": []}

    # TODO: is there a faster way to describe a bunch of Things?
    for item in query_response["Items"]:
        device_guid = item["device_guid"]["S"]
        try:
            describe_response = iot.describe_thing(thingName=device_guid)
        except iot.exceptions.ResourceNotFoundException:
            logger.warning("Device GUID %s not found in IoT", device_guid)
            continue

        device_attributes = describe_response.get("attributes")
        devices["devices"].append({
            "device_guid": device_guid,
            "serial_number": device_attributes.get("videon_serial_number"),
            "mac_address": device_attributes.get("videon_mac"),
            "partner_id": device_attributes.get("partner_id"),
            "model": device_attributes.get("model"),
            "manufacture_date": device_attributes.get("manufacture_date")
        })

    devices["pagination_token"] = query_response.get("NextToken")

    return devices
