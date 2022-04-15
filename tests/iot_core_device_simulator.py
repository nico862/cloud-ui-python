"""Simulates an IoT Core device pushing telemetry data to our IoT Core rules
using basic ingest.  Use this to validate your rules are actually firing.

"""

import boto3
import json
import random
import time

# TODO: Fetch the IoT endpoint from an environment variable similar to
# API_GATEWAY_URL.  It should already be in the CDK outputs JSON.
client = boto3.client(service_name="iot-data",
                      endpoint_url="https://device.dev01.videoncloud.com")

while 1:
    payload = {
        "cpu_utilization": random.randint(30, 70),
        "memory_utilization": random.randint(20, 80),
        "temperature_deg_c": random.randint(45, 47),
        "network_in_mbit_sec": random.randint(1, 10),
        "network_out_mbit_sec": random.randint(100, 300),
    }
    print(json.dumps(payload))
    client.publish(
        topic=
        "$aws/rules/device_health_metrics/0feef912-520b-40c2-a675-38ad948c4f93",
        payload=bytearray(json.dumps(payload), encoding="utf-8"))
    time.sleep(60)
