"""Request Handler for /devices/{device_guid} API Route

This is implemented as a Lambda Proxy integration.  The function is
responsible for validating the input, and sending a properly-formatted
response.  (Failure to do so will be a 5xx error for the client.)

https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
https://docs.aws.amazon.com/apigateway/latest/developerguide/handle-errors-in-lambda-integration.html
"""
import logging
from os import environ

# Enable X-Ray Tracing
from aws_xray_sdk.core import patch_all
import boto3

import videon_shared as videon

patch_all()

logger = logging.getLogger()

dynamodb = boto3.client("dynamodb")
iot = boto3.client("iot")

DEVICE_ORG_TABLE_NAME = environ.get("DEVICE_ORG_TABLE_NAME")


def lambda_handler(event, context):  # pylint: disable=unused-argument

    videon.setup_logging(logging.INFO, event)

    # Basic sanity checks (things that should never happen)
    # If these fail the API Gateway is probably misconfigured
    supported_methods = ("GET", "PATCH", "DELETE", "OPTIONS")
    assert event["httpMethod"] in supported_methods
    assert "Device" in event["requestContext"]["operationName"]
    assert event["pathParameters"].get("device_guid") is not None

    if event["httpMethod"] == "OPTIONS":
        return videon.response_cors(", ".join(supported_methods))

    response_json = {"error_code": "UNHANDLED_CONDITION"}
    response_code = 500

    device_guid = event["pathParameters"]["device_guid"]

    if event.get("body") is not None:
        try:
            body = videon.convert_request_body(event["body"])
        except videon.RequestBodyError as err:
            response_json = {"message": str(err)}
            response_code = 400
            return videon.response_json(response_code, response_json, event)
    else:
        body = None

    # TODO: check if user has permissions for this action
    # e.g. they are in the specified org, or appropriate cognito group,
    #      or internal auth

    try:
        if event["httpMethod"] == "GET":
            response_json = get_device(device_guid)
        elif event["httpMethod"] == "DELETE":
            assert "reason" in body
            response_json = delete_device(device_guid, body["reason"])
        elif event["httpMethod"] == "PATCH":
            response_json = update_device(device_guid, body)
        response_code = 200
    except videon.ResourceNotFoundError:
        response_json = {"message": "Device not found"}
        response_code = 404

    return videon.response_json(response_code, response_json, event)


def get_device(device_guid):
    get_response = dynamodb.get_item(TableName=DEVICE_ORG_TABLE_NAME,
                                     Key={"device_guid": {
                                         "S": device_guid
                                     }},
                                     ConsistentRead=True)

    logger.info("DynamoDB GET device GUID %s response: %s", device_guid,
                get_response)

    device = get_response.get("Item")

    if not device:
        raise videon.ResourceNotFoundError

    device_guid = device["device_guid"]["S"]
    try:
        describe_response = iot.describe_thing(thingName=device_guid)
    except iot.exceptions.ResourceNotFoundException as err:
        raise videon.ResourceNotFoundError from err

    device_attributes = describe_response.get("attributes")

    return {
        "device": {
            "device_guid": device_guid,
            "serial_number": device_attributes.get("videon_serial_number"),
            "mac_address": device_attributes.get("videon_mac"),
            "partner_id": device_attributes.get("partner_id"),
            "model": device_attributes.get("model"),
            "manufacture_date": device_attributes.get("manufacture_date")
        }
    }


def update_device(device_guid, payload):  # pylint: disable=unused-argument
    if payload is None:
        return {"message": "Device successfully updated"}

    # TODO: implement
    return {"message": "Device successfully updated"}


def delete_device(device_guid, reason):
    get_response = dynamodb.get_item(TableName=DEVICE_ORG_TABLE_NAME,
                                     Key={"device_guid": {
                                         "S": device_guid
                                     }},
                                     ConsistentRead=True)

    device = get_response.get("Item")

    if not device:
        raise videon.ResourceNotFoundError

    dynamodb.delete_item(TableName=DEVICE_ORG_TABLE_NAME,
                         Key={"device_guid": {
                             "S": device_guid
                         }})

    logger.info("Device %s deleted. Reason: %s", device_guid, reason)

    # TODO: reset device back to unpaired state in IoT

    return {"message": "Device successfully deleted"}
