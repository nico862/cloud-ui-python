"""Event Handler for state change events

This lambda is triggered whenever an entry in the device state table is
modified. It then creates an entry in the device events table with the
data from the state change.
"""
import datetime
import logging
from os import environ
import uuid

# Enable X-Ray Tracing
from aws_xray_sdk.core import patch_all
import boto3

import videon_shared as videon

DEVICE_EVENTS_TABLE_NAME = environ.get("DEVICE_EVENTS_TABLE_NAME")

patch_all()

logger = logging.getLogger()

dynamodb = boto3.client("dynamodb")


def lambda_handler(event, context):  # pylint: disable=unused-argument

    videon.setup_logging(logging.INFO, event)

    logger.info("Received event: %s", event)
    for record in event["Records"]:
        # We should never get anything but a MODIFY/INSERT event,
        # but just in case we do, skip it
        if record.get("eventName") not in ("MODIFY", "INSERT"):
            logger.warning("Received event other than a table update")
            continue

        # If we can't associate the event with a device, skip it
        try:
            device_guid = record["dynamodb"]["Keys"]["device_guid"]["S"]
        except KeyError:
            continue

        # Format the event and add it to the events table
        event_guid = str(uuid.uuid4())

        event_data = {}
        event_data["message"] = {"S": "State changed"}

        if record["eventName"] == "INSERT":
            event_data["from_state"] = {"M": {}}  # No old data when inserting
        else:
            event_data["from_state"] = {"M": record["dynamodb"]["OldImage"]}

        event_data["to_state"] = {"M": record["dynamodb"]["NewImage"]}

        logger.debug(event_data)

        # Generate timestamps - Using current time with microsecond precision
        event_datetime = datetime.datetime.utcnow()
        event_timestamp = event_datetime.isoformat(
            timespec="microseconds") + "Z"

        # For now, all event expire after 30 days
        event_lifespan_days = 30
        expires_datetime = event_datetime + datetime.timedelta(
            days=event_lifespan_days)
        expires_timestamp = expires_datetime.timestamp()

        write_attempts = 0
        max_write_attempts = 2
        while write_attempts < max_write_attempts:
            try:
                dynamodb.put_item(
                    TableName=DEVICE_EVENTS_TABLE_NAME,
                    Item={
                        "device_guid": {
                            "S": device_guid
                        },
                        "timestamp": {
                            "S": event_timestamp
                        },
                        "date": {
                            "S": event_timestamp[0:10]
                        },
                        "event_guid": {
                            "S": event_guid
                        },
                        "event_type": {
                            "S": "state"
                        },
                        "event_data": {
                            "M": event_data
                        },
                        "expires": {
                            "N": str(expires_timestamp)
                        }
                    },
                    ConditionExpression="attribute_not_exists(device_guid)")
            except dynamodb.exceptions.ConditionalCheckFailedException as err:
                if write_attempts == max_write_attempts:
                    raise err

                # If we somehow already have this exact timestamp in the table,
                # regenerate the timestamp and try again
                event_datetime = datetime.datetime.utcnow()
                event_timestamp = event_datetime.isoformat(
                    timespec="microseconds") + "Z"
                continue
            break
