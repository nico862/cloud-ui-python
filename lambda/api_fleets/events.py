"""Request Handler for /fleets/{guid}/events

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
    fleet_guid = path_params.get("fleet_guid")
    assert fleet_guid is not None

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

    if event["httpMethod"] == "GET":
        query_string_params = event.get("queryStringParameters", {})
        if query_string_params is None:
            query_string_params = {}

        array_query_string_params = event.get("multiValueQueryStringParameters",
                                              {})
        if array_query_string_params is None:
            array_query_string_params = {}

        # Get all of the org's devices
        device_guids = get_fleet_devices(fleet_guid)

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


def get_fleet_devices(fleet_guid: str) -> list:
    fleet_devices_url = f"{RESTAPI_URL_PATH}fleets/{fleet_guid}/devices"
    payload = {"pagination_size": videon.PAGINATION_SIZE_MAX}
    fleet_devices = []

    while True:
        get_devices_response = requests.get(fleet_devices_url,
                                            params=payload,
                                            headers=VIDEON_INTERNAL_HEADERS)

        assert get_devices_response.status_code == 200
        get_devices_response_json = get_devices_response.json()
        assert get_devices_response_json is not None

        for device in get_devices_response_json["devices"]:
            fleet_devices.append(device["device_guid"])

        if get_devices_response_json.get("pagination_token") is None:
            break
        else:
            payload["pagination_token"] = get_devices_response_json[
                "pagination_token"]

    return fleet_devices
