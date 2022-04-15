"""Request Handler for /devices/metrics and /devices/{guid}/metrics API Routes

This is implemented as a Lambda Proxy integration.  The function is
responsible for validating the input, and sending a properly-formatted
response.  (Failure to do so will be a 5xx error for the client.)

https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
https://docs.aws.amazon.com/apigateway/latest/developerguide/handle-errors-in-lambda-integration.html
"""
import datetime
import logging
from typing import Union

# Enable X-Ray Tracing
from aws_xray_sdk.core import patch_all
import boto3
import botocore.exceptions

import videon_shared as videon

patch_all()

logger = logging.getLogger()

cloudwatch = boto3.client("cloudwatch")
cloudwatch_paginator_get_metric_data = cloudwatch.get_paginator(
    "get_metric_data")

VIDEON_NAMESPACE_PREFIX = "Videon/Custom/"


def lambda_handler(event, context):  # pylint: disable=unused-argument

    videon.setup_logging(logging.INFO, event)

    # Basic sanity checks (things that should never happen)
    # If these fail the API Gateway is probably misconfigured
    supported_methods = ("GET", "POST", "OPTIONS")
    assert event["httpMethod"] in supported_methods
    assert "Metrics" in event["requestContext"]["operationName"]

    if event["httpMethod"] == "OPTIONS":
        return videon.response_cors(", ".join(supported_methods))

    response_json = {"error_code": "UNHANDLED_CONDITION"}
    response_code = 500

    # TODO: verify user has permission to access this device

    if event.get("body") is not None:
        try:
            body = videon.convert_request_body(event["body"])
        except videon.RequestBodyError as err:
            response_json = {"message": str(err)}
            return videon.response_json(400, response_json, event)

    if event["httpMethod"] == "GET":
        response_code = 200
        response_json = list_metrics()
    elif event["httpMethod"] == "POST":
        assert body
        assert "start_time" in body
        assert "end_time" in body
        assert "metrics" in body

        path_params = event.get("pathParameters")
        if path_params is not None:
            device_guid = path_params.get("device_guid")
        else:
            device_guid = None

        if device_guid is None:
            assert "device_guids" in body
            device_guids = list(set(body["device_guids"]))  # Remove duplicates
        else:
            device_guids = [device_guid]

        # Validate everything required is present and within allowed values
        pagination_token = body.get("pagination_token")
        pagination_size = body.get("pagination_size")
        try:
            pagination_size = videon.validate_pagination_size(pagination_size)
        except (TypeError, ValueError) as err:
            response_json = {"message": "Invalid pagination size. " + str(err)}
            response_code = 400
            return videon.response_json(response_code, response_json, event)

        try:
            start_time = videon.get_datetime_from_iso8601(body["start_time"])
            end_time = videon.get_datetime_from_iso8601(body["end_time"])

            # Time delta must be positive (can't have negative time range)
            assert (end_time - start_time).total_seconds() > 0
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

        scan_by_options = ["TimestampDescending", "TimestampAscending"]
        scan_by = body.get("scan_by", "TimestampDescending")
        if scan_by not in scan_by_options:
            response_json = {
                "message": "Invalid value given for scan_by. "
                           f"Must be one of {scan_by_options}"
            }
            response_code = 400
            return videon.response_json(response_code, response_json, event)

        metrics = body["metrics"]
        if not metrics:
            response_json = {
                "message": "At least one metrics object is required."
            }
            response_code = 400
            return videon.response_json(response_code, response_json, event)

        invalid_attributes = {}
        for metric in metrics:
            try:
                # There are so many rules for period, that I'm only validating
                # the value is an integeer and a min of 1. The API definition
                # explains if the period given is invalid, you will receive
                # 0 results
                metric["period"] = videon.validate_numeric_param_value(
                    metric["period"], min=1, integer=True)
            except (TypeError, ValueError) as err:
                invalid_attributes.add(str(err))

        if invalid_attributes:
            response_code = 400
            response_json = {
                "message": ("One or more metrics has an invalid period"
                            f"errors: {invalid_attributes}")
            }
            return videon.response_json(response_code, response_json, event)

        # Set up encryption key for pagination token
        pagination_encryption_key = videon.pagination_encryption_key(
            context.function_name, videon.get_authorizer_guid(event),
            videon.is_internal_auth(event))

        try:
            decrypted_pagination_token = videon.pagination_decrypt(
                pagination_token, pagination_encryption_key)

            response_json = get_device_metrics(device_guids, metrics,
                                               start_time, end_time, scan_by,
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


def get_device_metrics(device_guids: list, metrics: list, start_time: datetime,
                       end_time: datetime, scan_by: str, pagination_size: int,
                       pagination_token: Union[str, None]) -> dict:
    pagination_config = {}
    pagination_config["MaxItems"] = pagination_size
    if pagination_token is not None:
        pagination_config["StartingToken"] = pagination_token

    # Set up the data in the format needed for the request
    metric_data_queries = []
    for ndx, metric in enumerate(metrics):
        for device_guid in device_guids:
            dimensions = [{"Name": "device_guid", "Value": device_guid}]

            metric_info = {
                "Namespace": f"{VIDEON_NAMESPACE_PREFIX}{metric['namespace']}",
                "MetricName": metric["metric_name"],
                "Dimensions": dimensions
            }

            metric_stat = {
                "Metric": metric_info,
                "Period": metric["period"],
                "Stat": metric["statistic"]
            }

            device_guid_id_safe = device_guid.replace("-", "_")
            query = {
                "Id": f"m{ndx}_{device_guid_id_safe}",
                "MetricStat": metric_stat
            }

            if "label" in metric:
                query["Label"] = metric["label"]

            metric_data_queries.append(query)

    try:
        get_response = cloudwatch_paginator_get_metric_data.paginate(
            MetricDataQueries=metric_data_queries,
            StartTime=start_time,
            EndTime=end_time,
            ScanBy=scan_by,
            PaginationConfig=pagination_config).build_full_result()
    except botocore.exceptions.ParamValidationError as err:
        # "Invalid type for parameter ExclusiveStartKey" in the error message
        # means that the pagination token was invalid
        if "ExclusiveStartKey" in str(err):
            raise videon.PaginationTokenError(
                "Invalid pagination token") from err
        raise err
    except botocore.exceptions.ClientError as err:
        # Sample error message:
        # "ClientError: An error occurred (ValidationError) when calling the
        # GetMetricData operation: The value test for parameter
        # MetricDataQueries.member.2.MetricStat.Stat is not a valid statistic."
        #
        # Right now, I'm only aware of invalid values for statistic showing
        # up, but keeping the if statements separate in case others come
        # along
        if "ValidationError" in str(err):
            if "not a valid statistic" in str(err):
                raise ValueError(
                    "One or more metrics has an invalid value for statistic"
                ) from err
        raise err

    logger.info("DynamoDB GET metrics response: %s", get_response)

    # Log a warning if any messages are present
    if get_response.get("Messages", []):
        logger.warning("Received messages about the GetMetricDataOperation: %s",
                       get_response["Messages"])

    metrics_output = []
    if "MetricDataResults" in get_response:
        for metric_data in get_response["MetricDataResults"]:
            output_data = {}
            label = metric_data.get("Label", "")
            if VIDEON_NAMESPACE_PREFIX in label:
                label = label.replace(VIDEON_NAMESPACE_PREFIX, "")

            output_data["label"] = label
            output_data["timestamps"] = metric_data.get("Timestamps", [])
            output_data["values"] = metric_data.get("Values", [])

            metrics_output.append(output_data)

            # Log a warning if any messages are present
            if "Messages" in metric_data:
                logger.warning("Received messages about metric ID %s - %s: %s",
                               metric_data.get("Id", ""),
                               metric_data.get("Label", ""),
                               metric_data["Messages"])

    pagination_token = get_response.get("NextToken")

    return {"metrics": metrics_output, "pagination_token": pagination_token}


def list_metrics():
    metric_names = {}

    # TODO: don't hardcode these
    metric_names["cpu"] = [
        "cpu_load1",
        "cpu_load5",
        "cpu_load15",
        "cpu_CPU0_percent_used",
        "cpu_CPU1_percent_used",
        "cpu_CPU2_percent_used",
        "cpu_CPU3_percent_used",
    ]

    metric_names["thermal"] = [
        "thermal_pm8994_tz_temp_current",
        "thermal_pm8994_tz_temp_high",
        "thermal_pm8994_tz_temp_critical",
    ]

    metric_names["network"] = [
        "network_eth0_active",
        "network_eth0_speed",
        "network_eth0_mtu_bytes",
        "network_eth0_bytes_sent",
        "network_eth0_bytes_received",
        "network_lo_active",
        "network_lo_speed",
        "network_lo_mtu_bytes",
        "network_lo_bytes_sent",
        "network_lo_bytes_received",
    ]

    metric_names["memory"] = [
        "memory_system_bytes_total",
        "memory_system_bytes_free",
        "memory_system_percent_used",
    ]

    metric_names["filesystem"] = [
        "filesystem_/persist_bytes_total",
        "filesystem_/persist_bytes_free",
        "filesystem_/persist_percent_used",
        "filesystem_/data_bytes_total",
        "filesystem_/data_bytes_free",
        "filesystem_/data_percent_used",
        "filesystem_/cache_bytes_total",
        "filesystem_/cache_bytes_free",
        "filesystem_/cache_percent_used",
    ]

    return metric_names
