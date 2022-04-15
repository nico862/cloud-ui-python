"""Request Handler for /devices/events and /devices/{guid}/events API Routes

This is implemented as a Lambda Proxy integration.  The function is
responsible for validating the input, and sending a properly-formatted
response.  (Failure to do so will be a 5xx error for the client.)

https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
https://docs.aws.amazon.com/apigateway/latest/developerguide/handle-errors-in-lambda-integration.html
"""
from datetime import datetime, timedelta, timezone
import json
import logging
from os import environ
from typing import Union

# Enable X-Ray Tracing
from aws_xray_sdk.core import patch_all
import boto3
from boto3.dynamodb.types import TypeDeserializer
import botocore.exceptions

import videon_shared as videon

patch_all()

logger = logging.getLogger()

dynamodb = boto3.client("dynamodb")
dynamo_paginator_query = dynamodb.get_paginator("query")
deserializer = TypeDeserializer()

DEVICE_EVENTS_TABLE_NAME = environ.get("DEVICE_EVENTS_TABLE_NAME")


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

    # TODO: verify user has permission to access this device

    if event["httpMethod"] == "GET":
        query_string_params = event.get("queryStringParameters", {})
        if query_string_params is None:
            query_string_params = {}

        array_query_string_params = event.get("multiValueQueryStringParameters",
                                              {})
        if array_query_string_params is None:
            array_query_string_params = {}

        path_params = event.get("pathParameters")
        if path_params is not None:
            device_guid = path_params.get("device_guid")
        else:
            device_guid = None

        if device_guid is None:
            assert "device_guids" in array_query_string_params
            device_guids = list(set(
                array_query_string_params["device_guids"]))  # Remove duplicates
        else:
            device_guids = [device_guid]

        event_types = array_query_string_params.get("event_types", [])

        start_time = query_string_params.get("start_time")
        end_time = query_string_params.get("end_time")

        # Make sure if we are looking up multiple devices, we have a start_time
        if len(device_guids) > 1 and not start_time:
            response_json = {
                "message": "Missing required request parameters: [start_time]"
            }
            response_code = 400
            return videon.response_json(response_code, response_json, event)

        try:
            if start_time:
                start_time = videon.iso8601_to_utc(start_time)
            if end_time:
                end_time = videon.iso8601_to_utc(end_time)

            if start_time and end_time:
                assert end_time > start_time
        except ValueError:
            response_json = {
                "message":
                    "Invalid value given for start_time and / or end_time."
            }
            response_code = 400
            return videon.response_json(response_code, response_json, event)
        except AssertionError:
            response_json = {
                "message": "end_time must be greater than start_time."
            }
            response_code = 400
            return videon.response_json(response_code, response_json, event)

        pagination_token = query_string_params.get("pagination_token")
        pagination_size = query_string_params.get(
            "pagination_size", videon.PAGINATION_SIZE_DEFAULT)

        try:
            pagination_size = videon.validate_pagination_size(pagination_size)
        except (TypeError, ValueError) as err:
            response_json = {"message": "Invalid pagination size. " + str(err)}
            response_code = 400
            return videon.response_json(response_code, response_json, event)

        # Set up encryption key for pagination token
        pagination_encryption_key = videon.pagination_encryption_key(
            context.function_name, videon.get_authorizer_guid(event),
            videon.is_internal_auth(event))

        try:
            decrypted_pagination_token = videon.pagination_decrypt(
                pagination_token, pagination_encryption_key)

            if len(device_guids) == 1:
                response_json = get_device_events(device_guids[0], event_types,
                                                  start_time, end_time,
                                                  pagination_size,
                                                  decrypted_pagination_token)
            else:
                response_json = get_devices_events(device_guids, event_types,
                                                   start_time, end_time,
                                                   pagination_size,
                                                   decrypted_pagination_token)

            response_json["pagination_token"] = videon.pagination_encrypt(
                response_json.get("pagination_token"),
                pagination_encryption_key)

            response_code = 200
        except (videon.PaginationTokenError, ValueError) as err:
            response_json = {"message": str(err)}
            response_code = 400

    return videon.response_json(response_code, response_json, event)


def get_device_events(device_guid: str, event_types: list,
                      start_time: Union[str, None], end_time: Union[str, None],
                      pagination_size: int, pagination_token: Union[str, None]):
    pagination_config = {}
    pagination_config["MaxItems"] = pagination_size
    if pagination_token is not None:
        pagination_config["StartingToken"] = pagination_token

    event_output = {"events": []}

    query_args = {
        "TableName": DEVICE_EVENTS_TABLE_NAME,
        "PaginationConfig": pagination_config,
        "ScanIndexForward": False
    }
    expression_values = {":device_guid": {"S": device_guid}}
    key_condition_expression = "device_guid = :device_guid"

    # Create a filter if given any event filter attributes
    filter_expression = ""
    for ndx, event_type in enumerate(event_types):
        event_type_name = f":event_type_{ndx}"
        expression_values[event_type_name] = {"S": event_type}
        if filter_expression != "":
            filter_expression += " OR "
        filter_expression += f"event_type = {event_type_name}"

    expression_names = None
    if start_time and end_time:
        # Timestamp is a reserved keyword
        expression_names = {"#timestamp": "timestamp"}
        expression_values[":timestamp_start"] = {"S": start_time}
        expression_values[":timestamp_end"] = {"S": end_time}
        key_condition_expression += (" AND #timestamp BETWEEN "
                                     ":timestamp_start and :timestamp_end")
    elif start_time:
        # Timestamp is a reserved keyword
        expression_names = {"#timestamp": "timestamp"}
        expression_values[":timestamp_start"] = {"S": start_time}
        key_condition_expression += " AND #timestamp >= :timestamp_start"
    elif end_time:
        # Timestamp is a reserved keyword
        expression_names = {"#timestamp": "timestamp"}
        expression_values[":timestamp_end"] = {"S": end_time}
        key_condition_expression += " AND #timestamp <= :timestamp_end"

    if expression_names:
        query_args["ExpressionAttributeNames"] = expression_names
    if filter_expression:
        query_args["FilterExpression"] = filter_expression

    query_args["ExpressionAttributeValues"] = expression_values
    query_args["KeyConditionExpression"] = key_condition_expression

    logger.debug("DynamoDB GET events request: %s", query_args)

    try:
        query_response = dynamo_paginator_query.paginate(
            **query_args).build_full_result()
    except botocore.exceptions.ParamValidationError as err:
        if "ExclusiveStartKey" in str(err):
            raise videon.PaginationTokenError from err
        raise err

    logger.info("DynamoDB GET events response: %s", query_response)

    for item in query_response["Items"]:
        # Unmarshal the event data
        event_data = item["event_data"]["M"]
        deserialized_event_data = {
            k: deserializer.deserialize(v) for k, v in event_data.items()
        }

        event = {
            "device_guid": device_guid,
            "event_guid": item["event_guid"]["S"],
            "timestamp": item["timestamp"]["S"],
            "event_type": item["event_type"]["S"],
            "event_data": deserialized_event_data,
        }
        event_output["events"].append(event)

    event_output["pagination_token"] = query_response.get("NextToken")
    return event_output


def get_devices_events(device_guids: list, event_types: list, start_time: str,
                       end_time: Union[str, None], pagination_size: int,
                       pagination_token: Union[str, None]) -> dict:
    if end_time is None:
        end_time = datetime.utcnow().isoformat(timespec="microseconds") + "Z"
    dates = date_range(start_time, end_time)

    # Timestamp and date are reserved keywords
    expression_names = {"#date": "date", "#timestamp": "timestamp"}
    expression_values = {
        ":timestamp_start": {
            "S": start_time
        },
        ":timestamp_end": {
            "S": end_time
        }
    }

    # Filter on device_guids and event types
    filter_expression = "("
    for ndx, device_guid in enumerate(device_guids):
        device_guid_name = f":device_guid_{ndx}"
        expression_values[device_guid_name] = {"S": device_guid}
        if ndx != 0:
            filter_expression += " OR "
        filter_expression += f"device_guid = {device_guid_name}"
    filter_expression += ")"

    for ndx, event_type in enumerate(event_types):
        event_type_name = f":event_type_{ndx}"
        expression_values[event_type_name] = {"S": event_type}
        if ndx == 0:
            filter_expression += " AND ("
        else:
            filter_expression += " OR "

        filter_expression += f"event_type = {event_type_name}"

        if ndx == (len(event_types) - 1):
            filter_expression += ")"

    # Set up pagination configuration
    pagination_config = {}
    if pagination_token is not None:
        pagination_token: dict = json.loads(pagination_token)
        pagination_offset = pagination_token["o"]  # Date offset
        pagination_token: str = pagination_token["t"]  # Actual token
        if pagination_token is not None:
            pagination_config["StartingToken"] = pagination_token
    else:
        pagination_offset = 0

    event_output = {"events": []}

    query_args = {
        "TableName": DEVICE_EVENTS_TABLE_NAME,
        "IndexName": "date",
        "ExpressionAttributeNames": expression_names,
        "FilterExpression": filter_expression,
        "ScanIndexForward": False
    }

    # Query each date until we reach the pagination size or end of data
    date_offset = pagination_offset
    response_pagination_token = None
    for date in dates[pagination_offset:]:
        pagination_config["MaxItems"] = pagination_size - len(
            event_output["events"])

        expression_values[":date"] = {"S": date}
        key_condition_expression = ("#date = :date AND #timestamp BETWEEN "
                                    ":timestamp_start and :timestamp_end")

        query_args["PaginationConfig"] = pagination_config
        query_args["ExpressionAttributeValues"] = expression_values
        query_args["KeyConditionExpression"] = key_condition_expression

        logger.debug("DynamoDB GET events request: %s", query_args)

        try:
            query_response = dynamo_paginator_query.paginate(
                **query_args).build_full_result()
        except botocore.exceptions.ParamValidationError as err:
            if "ExclusiveStartKey" in str(err):
                raise videon.PaginationTokenError from err
            raise err

        logger.info("DynamoDB GET events response: %s", query_response)

        for item in query_response["Items"]:
            # Unmarshal the event data
            event_data = item["event_data"]["M"]
            deserialized_event_data = {
                k: deserializer.deserialize(v) for k, v in event_data.items()
            }

            event = {
                "device_guid": item["device_guid"]["S"],
                "event_guid": item["event_guid"]["S"],
                "timestamp": item["timestamp"]["S"],
                "event_type": item["event_type"]["S"],
                "event_data": deserialized_event_data,
            }
            event_output["events"].append(event)

        # If pagination size is reached, keep track of which
        # date we are at and the pagination token
        if len(event_output["events"]) >= pagination_size:
            if query_response.get("NextToken") is not None:
                response_pagination_token = json.dumps({
                    "t": query_response.get("NextToken"),
                    "o": date_offset
                })
            else:
                # Look ahead to figure out if we are done yet or not
                next_date_offset = get_next_date_offset_with_data(
                    dates, date_offset + 1, query_args)
                if next_date_offset:
                    response_pagination_token = json.dumps({
                        "t": None,
                        "o": next_date_offset
                    })
            break

        date_offset += 1

    event_output["pagination_token"] = response_pagination_token
    return event_output


def date_range(start: str, end: str) -> list[str]:
    """Returns a list of dates between start and end (inclusive)
    in order from most recent to oldest

    :param start: ISO 8601 formatted string
    :param end: ISO 8601 formatted string
    :return List of dates
    """
    # Convert ISO8601 strings to datetime objects in UTC
    start_dt = videon.get_datetime_from_iso8601(start).astimezone(
        tz=timezone.utc)
    end_dt = videon.get_datetime_from_iso8601(end).astimezone(tz=timezone.utc)

    # Calculate timedelta and get all string dates
    dates = []
    delta = end_dt - start_dt
    for i in range(delta.days + 1):
        dt = end_dt - timedelta(days=i)
        date = dt.strftime("%Y-%m-%d")
        dates.append(date)

    return dates


def get_next_date_offset_with_data(dates: str, starting_date: int,
                                   query_args: dict):
    """Returns the next date offset that has data, starting at
    the starting_date index. If no data is found, returns None
    """
    date_offset = starting_date
    for date in dates[starting_date:]:
        expression_values = query_args["ExpressionAttributeValues"]
        pagination_config = query_args["PaginationConfig"]
        pagination_config["MaxItems"] = 1
        del pagination_config["StartingToken"]

        expression_values[":date"] = {"S": date}
        key_condition_expression = ("#date = :date AND #timestamp BETWEEN "
                                    ":timestamp_start and :timestamp_end")

        query_args["ExpressionAttributeValues"] = expression_values
        query_args["KeyConditionExpression"] = key_condition_expression

        query_response = dynamo_paginator_query.paginate(
            **query_args).build_full_result()

        if query_response["Items"]:
            return date_offset

        date_offset += 1

    return None
