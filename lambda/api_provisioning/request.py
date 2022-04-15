"""Request Handler for /provisioning/request API Route

This is implemented as a Lambda Proxy integration.  The function is
responsible for validating the input, and sending a properly-formatted
response.  (Failure to do so will be a 5xx error for the client)

https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
https://docs.aws.amazon.com/apigateway/latest/developerguide/handle-errors-in-lambda-integration.html
"""
import io
import logging
import os
from os import environ
import shutil
import tarfile
import uuid

from aws_xray_sdk.core import patch_all  # Enable X-Ray Tracing
import boto3

import videon_shared as videon

patch_all()

dynamodb = boto3.client("dynamodb")
iot = boto3.client("iot")

logger = logging.getLogger()

PROVISIONING_REQ_TABLE_NAME = environ.get("PROVISIONING_REQ_TABLE_NAME")
IOT_DEVICE_POLICY_NAME = environ.get("IOT_DEVICE_POLICY_NAME")
AMAZON_ROOT_CERT_VALUE = environ.get("AMAZON_ROOT_CERT_VALUE")


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
        assert "provisioning_token" in body

        serial_number = body["serial_number"]
        mac_address = body["mac_address"]
        provisioning_token = body["provisioning_token"]

        try:
            response_body = execute_provisioning_request(
                serial_number, mac_address, provisioning_token)
            response_code = 201
            return videon.response_binary(response_code, response_body, event)
        except videon.ResourceNotFoundError:
            response_json = {"message": "Provisioning request not found"}
            response_code = 404

    return videon.response_json(response_code, response_json, event)


def execute_provisioning_request(serial_number: str, mac_address: str,
                                 provisioning_token: str) -> bytes:
    token_hash = videon.get_sha256_hash(provisioning_token)
    logger.info("Provisioning request received: SN: %s, Mac: %s, Hash: %s",
                serial_number, mac_address, token_hash)

    get_response = dynamodb.get_item(
        TableName=PROVISIONING_REQ_TABLE_NAME,
        Key={
            "mac_address": {
                "S": mac_address
            },
            "serial_number": {
                "S": serial_number
            }
        },
        ConsistentRead=True,
    )

    item = get_response.get("Item")

    if not item or item["token_hash"]["S"] != token_hash:
        raise videon.ResourceNotFoundError

    # Check if Thing already exists for the serial number
    iot_response = iot.list_things(attributeName="videon_serial_number",
                                   attributeValue=serial_number)
    things = iot_response["things"]

    thing_name = str(uuid.uuid4())

    # Create a Key and Certificate in the AWS IoT Service per Thing
    keys_cert = iot.create_keys_and_certificate(setAsActive=True)
    cert_arn = keys_cert["certificateArn"]

    # Create a tar with all of the certs/keys needed for provisioning
    tar_data_bytes = get_keys_and_certificates_tar(thing_name, keys_cert)

    # Attach our policy to the newly created key
    iot.attach_policy(policyName=IOT_DEVICE_POLICY_NAME, target=cert_arn)

    # Create a Thing with the given attributes
    iot.create_thing(thingName=thing_name,
                     thingTypeName="VideonEncoderV1",
                     attributePayload={
                         "attributes": {
                             "videon_serial_number": serial_number,
                             "videon_mac": mac_address,
                             "model": "LiveEdgeV0.1"
                         },
                         "merge": False
                     })

    # Attach the previously created Certificate to the created Thing
    iot.attach_thing_principal(thingName=thing_name, principal=cert_arn)

    logger.info("Thing: '%s' created. Associated with cert:'%s'", thing_name,
                cert_arn)

    for thing in things:
        old_thing_name = thing["thingName"]
        logger.info(
            "Force overwrite requested: Deleting Thing %s "
            "which has the same serial number", old_thing_name)
        try:
            delete_thing(old_thing_name)
        except Exception as e:
            logger.warning(
                "Failed to delete Thing %s. Multiple Things exist "
                "with serial number %s", old_thing_name, serial_number)
            raise e

    # Delete the request only after everything else succeeds
    dynamodb.delete_item(TableName=PROVISIONING_REQ_TABLE_NAME,
                         Key={
                             "mac_address": {
                                 "S": mac_address
                             },
                             "serial_number": {
                                 "S": serial_number
                             }
                         })

    return tar_data_bytes


def get_keys_and_certificates_tar(thing_name: str, keys_cert: dict) -> bytes:
    # Write all of the certs to files and put in a tar
    cert_file = "certificate.pem.crt"
    private_key_file = "private.pem.key"
    device_guid_file = "device_guid"
    amazon_root_cert_file = "root-CA.crt"

    try:
        os.chdir("/tmp")  # Must do this first to have write permissions
        thing_dir = f"/tmp/{thing_name}"
        os.mkdir(thing_dir)
        os.chdir(thing_dir)

        with open(cert_file, "w") as pem_file:
            pem = keys_cert["certificatePem"]
            pem_file.write(pem)
            logger.info("Thing Name: %s and PEM file: %s", thing_name,
                        cert_file)

        with open(private_key_file, "w") as prv_file:
            prv = keys_cert["keyPair"]["PrivateKey"]
            prv_file.write(prv)
            logger.info("Thing Name: %s Private Key File: %s", thing_name,
                        private_key_file)

        with open(device_guid_file, "w") as guid_file:
            guid_file.write(thing_name)

        with open(amazon_root_cert_file, "w") as amazon_cert:
            amazon_cert.write(AMAZON_ROOT_CERT_VALUE)

        # Create a tar of the directory with the files
        tar_file_name = f"Archive-{thing_name}"
        with tarfile.open(tar_file_name, "w:") as tar:
            tar.add(cert_file)
            tar.add(private_key_file)
            tar.add(device_guid_file)
            tar.add(amazon_root_cert_file)

        # Get the tar as binary data
        with open(tar_file_name, "rb") as tar:
            tar_data = io.BytesIO(tar.read())

        # Data in /tmp doesn't stick around very long but try to
        # delete the files anyways since:
        # "The same Lambda execution environment may be reused by multiple
        # Lambda invocations to optimize performance. The /tmp area is
        # preserved for the lifetime of the execution environment"
        os.chdir("/tmp")
        shutil.rmtree(thing_dir, ignore_errors=True)

    except OSError as ose:
        logger.info("OSError while writing an ELF file. %s", ose)
        raise ose

    return tar_data.getvalue()


def delete_thing(thing_name: str) -> None:
    # Get thing cert/principal
    principals = iot.list_thing_principals(
        maxResults=5, thingName=thing_name).get("principals")

    if principals:
        principal_arn = principals[0]
        certificate_id = principal_arn.split("/")[-1]
        # Detach Policy from cert/principal
        iot.detach_policy(policyName=IOT_DEVICE_POLICY_NAME,
                          target=principal_arn)
        # Detach thing from cert/principal
        iot.detach_thing_principal(thingName=thing_name,
                                   principal=principal_arn)
        # Deactivate the cert/principal
        iot.update_certificate(certificateId=certificate_id,
                               newStatus="INACTIVE")
        # Delete the cert/principal
        iot.delete_certificate(certificateId=certificate_id, forceDelete=True)

    # Delete the Thing
    iot.delete_thing(thingName=thing_name)

    logger.info("Deleted Thing %s ", thing_name)
