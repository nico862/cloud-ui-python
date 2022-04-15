"""Request Handler for /devices/adopt API Route

This is implemented as a Lambda Proxy integration.  The function is
responsible for validating the input, and sending a properly-formatted
response.  (Failure to do so will be a 5xx error for the client.)

https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
https://docs.aws.amazon.com/apigateway/latest/developerguide/handle-errors-in-lambda-integration.html
"""
import logging
from os import environ
from requests.structures import CaseInsensitiveDict

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
    supported_methods = ("POST", "OPTIONS")
    assert event["httpMethod"] in supported_methods
    assert "Adopt" in event["requestContext"]["operationName"]

    if event["httpMethod"] == "OPTIONS":
        return videon.response_cors(", ".join(supported_methods))

    response_json = {"error_code": "UNHANDLED_CONDITION"}
    response_code = 500

    # TODO: check if user has permissions for this action
    # e.g. appropriate cognito group

    if event["httpMethod"] == "POST":
        query_string_params = event.get("queryStringParameters")
        assert query_string_params is not None

        serial_number = query_string_params.get("serial_number")
        assert serial_number is not None

        org_guid = query_string_params.get("org_guid")

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

        try:
            response_json = adopt_device(serial_number, org_guid)
            response_code = 200
        except videon.ResourceNotFoundError:
            response_json = {"message": "Device not found"}
            response_code = 404
        except videon.ResourceConflictError:
            response_json = {
                "message": ("Multiple devices found "
                            "with given serial number")
            }
            response_code = 409

    return videon.response_json(response_code, response_json, event)


def adopt_device(serial_number, org_guid):
    iot_response = iot.list_things(attributeName="videon_serial_number",
                                   attributeValue=serial_number)
    logger.info(iot_response)
    things = iot_response["things"]

    if not things:
        raise videon.ResourceNotFoundError

    # If we found more than 1 device with that serial number,
    # something is wrong
    if len(things) != 1:
        raise videon.ResourceConflictError

    device = things[0]
    device_guid = device["thingName"]

    logger.info("Adopting device GUID: %s by organization %s", device_guid,
                org_guid)

    dynamodb.put_item(TableName=DEVICE_ORG_TABLE_NAME,
                      Item={
                          "device_guid": {
                              "S": device_guid
                          },
                          "org_guid": {
                              "S": org_guid
                          }
                      })

    device_attributes = device.get("attributes")
    return {
        "message": "Device successfully adopted",
        "device": {
            "device_guid": device_guid,
            "serial_number": device_attributes.get("videon_serial_number"),
            "mac_address": device_attributes.get("videon_mac"),
            "partner_id": device_attributes.get("partner_id"),
            "model": device_attributes.get("model"),
            "manufacture_date": device_attributes.get("manufacture_date")
        }
    }
