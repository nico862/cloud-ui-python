"""Request Handler for /provisioning/authorize API Route

This is implemented as a Lambda Proxy integration.  The function is
responsible for validating the input, and sending a properly-formatted
response.  (Failure to do so will be a 5xx error for the client)

https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
https://docs.aws.amazon.com/apigateway/latest/developerguide/handle-errors-in-lambda-integration.html
"""
import datetime
import logging
from os import environ
import re

from aws_xray_sdk.core import patch_all  # Enable X-Ray Tracing
import boto3

import videon_shared as videon

patch_all()

dynamodb = boto3.client("dynamodb")
iot = boto3.client("iot")
secret_manager = boto3.client("secretsmanager")

logger = logging.getLogger()

PROVISIONING_REQ_TABLE_NAME = environ.get("PROVISIONING_REQ_TABLE_NAME")

# Validation constants. Not validating in OpenAPI for security via obscurity
VIDEON_SN_REGEX = r"^(\d{4}-\d{4})$"  # Format NNNN-NNNN
# Valid starting numbers for EdgeCaster serial numbers
VIDEON_SN_PREFIXS = ("4717", "4730")
# Videon MAC address block
VIDEON_MAC_ADDR_OCTETS = ("00:25:4C")
# Valid starting numbers for Test Device serial numbers
VIDEON_TEST_SN_PREFIXS = ("4200")
# Videon Test Device MAC address block
VIDEON_TEST_MAC_ADDR_OCTETS = ("FE:ED:FA:CE")


def lambda_handler(event, context):  # pylint: disable=unused-argument
    videon.setup_logging(logging.INFO, event)

    # Basic sanity checks (things that should never happen)
    # If these fail the API Gateway is probably misconfigured
    supported_methods = ("POST", "OPTIONS")
    assert event["httpMethod"] in supported_methods
    assert "Provisioning" in event["requestContext"]["operationName"]

    if event["httpMethod"] == "OPTIONS":
        return videon.response_cors(", ".join(supported_methods))

    response_json = {"error_code": "UNHANDLED_CONDITION"}
    response_code = 500

    if event.get("body") is not None:
        try:
            body = videon.convert_request_body(event["body"])
        except videon.RequestBodyError as err:
            response_json = {"message": str(err)}
            response_code = 400
            return videon.response_json(response_code, response_json, event)

    if event["httpMethod"] == "POST":
        assert body
        assert "serial_number" in body
        assert "mac_address" in body

        serial_number = body["serial_number"]
        mac_address = body["mac_address"]
        force_overwrite = body.get("force", False)

        is_sn_valid = ((serial_number.startswith(VIDEON_SN_PREFIXS) or
                        (serial_number.startswith(VIDEON_TEST_SN_PREFIXS))) and
                       re.search(VIDEON_SN_REGEX, serial_number) is not None)

        is_mac_valid = ((mac_address.startswith(VIDEON_MAC_ADDR_OCTETS)) or
                        (mac_address.startswith(VIDEON_TEST_MAC_ADDR_OCTETS)))

        if not (is_sn_valid and is_mac_valid):
            response_json = {
                "message": ("Invalid request parameters: "
                            "[serial_number and / or mac_address]")
            }
            response_code = 400
            return videon.response_json(response_code, response_json, event)

        try:
            response_json = create_provisioning_request(serial_number,
                                                        mac_address,
                                                        force_overwrite)
            response_code = 201
        except videon.ResourceExistsError:
            response_json = {
                "message": ("Device with this serial number "
                            "already provisioned")
            }
            response_code = 409

    return videon.response_json(response_code, response_json, event)


def create_provisioning_request(serial_number: str, mac_address: str,
                                force_overwrite: bool) -> dict:
    # Check if Thing already exists for the serial number
    iot_response = iot.list_things(attributeName="videon_serial_number",
                                   attributeValue=serial_number)
    things = iot_response["things"]

    if things and not force_overwrite:
        raise videon.ResourceExistsError

    # Generate timestamp - Using current time with seconds precision
    issued_datetime = datetime.datetime.utcnow().replace(microsecond=0)
    issued_timestamp = issued_datetime.isoformat() + "Z"

    current_secret = secret_manager.get_secret_value(
        SecretId=environ["VIDEON_PROVISIONING_ARN"])["SecretString"]
    secret_hash = videon.get_sha256_hash(current_secret)

    # If item already exists in table, it will be replaced
    dynamodb.put_item(TableName=PROVISIONING_REQ_TABLE_NAME,
                      Item={
                          "mac_address": {
                              "S": mac_address
                          },
                          "serial_number": {
                              "S": serial_number
                          },
                          "token_hash": {
                              "S": secret_hash
                          },
                          "timestamp": {
                              "S": issued_timestamp
                          },
                      })

    return {"provisioning_token": current_secret}
