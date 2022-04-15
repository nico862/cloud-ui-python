"""Request Handler for /devices/{guid}/state API Route

This is implemented as a Lambda Proxy integration.  The function is
responsible for validating the input, and sending a properly-formatted
response.  (Failure to do so will be a 5xx error for the client.)

https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
https://docs.aws.amazon.com/apigateway/latest/developerguide/handle-errors-in-lambda-integration.html
"""
import datetime
import logging
from os import environ

# Enable X-Ray Tracing
from aws_xray_sdk.core import patch_all
import boto3

import videon_shared as videon

patch_all()

logger = logging.getLogger()

DEVICE_STATE_TABLE_NAME = environ.get("DEVICE_STATE_TABLE_NAME")
device_table = boto3.resource("dynamodb").Table(DEVICE_STATE_TABLE_NAME)


def lambda_handler(event, context):  # pylint: disable=unused-argument

    videon.setup_logging(logging.INFO, event)

    # Basic sanity checks (things that should never happen)
    # If these fail the API Gateway is probably misconfigured
    supported_methods = ("GET", "OPTIONS")
    assert event["httpMethod"] in supported_methods
    assert "DeviceState" in event["requestContext"]["operationName"]

    if event["httpMethod"] == "OPTIONS":
        return videon.response_cors(", ".join(supported_methods))

    response_json = {"error_code": "UNHANDLED_CONDITION"}
    response_code = 500

    device_guid = event["pathParameters"]["device_guid"]

    # TODO: verify user has permission to access this device

    if event["httpMethod"] == "GET":
        try:
            response_json = get_device_state(device_guid)
            response_code = 200
        except videon.ResourceNotFoundError:
            response_json = {
                "message": f"No state found for Device GUID {device_guid}"
            }
            response_code = 400

    return videon.response_json(response_code, response_json, event)


def get_device_state(device_guid: str) -> dict:
    get_response = device_table.get_item(Key={"device_guid": device_guid},
                                         ConsistentRead=True)
    logger.info("DynamoDB GET device GUID %s response: %s", device_guid,
                get_response)

    device = get_response.get("Item")

    if not device:
        raise videon.ResourceNotFoundError

    # Need to convert this one to ISO 8601
    if device.get("last_state_update") is not None:
        epoch_sec = device["last_state_update"] / 1000
        device["last_state_update"] = datetime.datetime.utcfromtimestamp(
            epoch_sec).isoformat() + "Z"

    # Return everything in the state table
    return {"state": device}
