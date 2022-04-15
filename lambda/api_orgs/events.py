"""Request Handler for /orgs/{guid}/events

This is implemented as a Lambda Proxy integration.  The function is
responsible for validating the input, and sending a properly-formatted
response.  (Failure to do so will be a 5xx error for the client.)

https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
https://docs.aws.amazon.com/apigateway/latest/developerguide/handle-errors-in-lambda-integration.html
"""
import logging
from os import environ
import requests

# Enable X-Ray Tracing
from aws_xray_sdk.core import patch_all
import boto3

import videon_shared as videon

patch_all()

logger = logging.getLogger()

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
    supported_methods = ("GET", "OPTIONS")
    assert event["httpMethod"] in supported_methods
    assert "Events" in event["requestContext"]["operationName"]

    if event["httpMethod"] == "OPTIONS":
        return videon.response_cors(", ".join(supported_methods))

    response_json = {"error_code": "UNHANDLED_CONDITION"}
    response_code = 500

    assert "pathParameters" in event
    path_params = event["pathParameters"]
    assert path_params is not None
    org_guid = path_params.get("org_guid")
    assert org_guid is not None

    # Validate access level within org before proceeding
    authorizer_guid = videon.get_authorizer_guid(event)
    authorizer_user_groups = videon.get_user_groups(event)
    is_org_manager = bool(
        COGNITO_ORG_MANAGEMENT_GROUP_NAME in authorizer_user_groups)

    if event["httpMethod"] == "GET":
        required_permission_levels = videon.Permissions.READER
    else:
        required_permission_levels = videon.Permissions.ADMIN

    try:
        if not videon.is_internal_auth(event) and not is_org_manager:
            videon.validate_user_org_access(authorizer_guid, org_guid,
                                            required_permission_levels,
                                            RESTAPI_URL_PATH,
                                            VIDEON_INTERNAL_HEADERS)
    except videon.PermissionsError:
        response_json = {
            "message": "User does not have permissions to perform this action."
        }
        return videon.response_json(403, response_json, event)
    except videon.ResourceNotFoundError:
        response_json = {
            "message": (f"Organization GUID {org_guid} does not exist, "
                        "or you do not have permission to access it.")
        }
        return videon.response_json(404, response_json, event)

    if event["httpMethod"] == "GET":
        query_string_params = event.get("queryStringParameters", {})
        if query_string_params is None:
            query_string_params = {}

        array_query_string_params = event.get("multiValueQueryStringParameters",
                                              {})
        if array_query_string_params is None:
            array_query_string_params = {}

        # Get all of the org's devices
        device_guids = get_org_devices(org_guid)

        if not device_guids:
            response_json = {"events": []}
            return videon.response_json(200, response_json, event)

        # Get the events for those devices
        events_url = f"{RESTAPI_URL_PATH}devices/events"
        payload = {
            "device_guids": device_guids,
            "event_types": array_query_string_params.get("event_types", []),
            "start_time": query_string_params.get("start_time"),
            "end_time": query_string_params.get("end_time"),
            "pagination_size": query_string_params.get("pagination_size"),
            "pagination_token": query_string_params.get("pagination_token"),
        }

        response = requests.get(events_url,
                                params=payload,
                                headers=VIDEON_INTERNAL_HEADERS)
        response_code = response.status_code
        response_json = response.json()

    return videon.response_json(response_code, response_json, event)


def get_org_devices(org_guid: str) -> list:
    devices_url = f"{RESTAPI_URL_PATH}devices/"
    payload = {
        "org_guid": org_guid,
        "pagination_size": videon.PAGINATION_SIZE_MAX
    }
    org_devices = []

    while True:
        get_devices_response = requests.get(devices_url,
                                            params=payload,
                                            headers=VIDEON_INTERNAL_HEADERS)

        assert get_devices_response.status_code == 200
        get_devices_response_json = get_devices_response.json()
        assert get_devices_response_json is not None

        for device in get_devices_response_json["devices"]:
            org_devices.append(device["device_guid"])

        if get_devices_response_json.get("pagination_token") is None:
            break
        else:
            payload["pagination_token"] = get_devices_response_json[
                "pagination_token"]

    return org_devices
