"""API Read-Only Integration Tests (Devices)

These tests should be run against deployed code, typically as part of a
CI/CD pipeline.

Expects the API_GATEWAY_URL environment variable to be populated with the full
URL of the API Gateway, including the stage name.
(e.g. https://api.example.com/v1/)

Read-only tests must not modify the application state in any way, should not
make any assumptions about existing data (databases could be blank, could be
full of garbage test data, or could be full of legitimate data), and should be
suitable for running against production.
"""
import requests
import os

from urllib.parse import urljoin

api_gateway_url = os.environ["API_GATEWAY_URL"]
test_account_auth_type = os.environ["TEST_AUTH_TYPE"]
test_account_auth_token = os.environ["TEST_AUTH_TOKEN"]
test_account_auth = f"{test_account_auth_type} {test_account_auth_token}"

devices_url = urljoin(api_gateway_url, "devices")
adopt_url = urljoin(api_gateway_url, "devices/adopt")
print(f"-- Test URL = {devices_url}")

headers = {"Authorization": test_account_auth}


def response_boilerplate_checks(response):
    """Check for standard fields that should be present in all of our
    responses.  Tests should call this function.
    """
    assert "operation_name" in response.json()
    assert len(response.json().get("operation_name")) > 4
    assert "api_request_id" in response.json()
    assert len(response.json().get("api_request_id")) == 36


# /devices
def test_get_devices_no_org_guid():
    response = requests.get(devices_url, headers=headers)
    assert response.status_code == 400
    assert "message" in response.json()
    response_boilerplate_checks(response)


def test_get_devices():
    # Using a fake org guid, should return an empty list of devices
    headers["Org-Guid"] = "fake-guid"
    response = requests.get(devices_url, headers=headers)
    assert response.status_code == 200
    assert "devices" in response.json()
    assert isinstance(response.json().get("devices"), list)
    response_boilerplate_checks(response)


def test_get_devices_invalid_token():
    headers["Org-Guid"] = "fake-guid"
    payload = {"pagination_token": "ABC"}
    response = requests.get(devices_url, headers=headers, params=payload)
    assert response.status_code == 400
    assert "message" in response.json()
    response_boilerplate_checks(response)


def test_get_devices_pagination_size_validation():
    headers["Org-Guid"] = "fake-guid"
    payload = {"pagination_size": 0}
    response = requests.get(devices_url, headers=headers, params=payload)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    payload = {"pagination_size": 61}
    response = requests.get(devices_url, headers=headers, params=payload)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    payload = {"pagination_size": "abc"}
    response = requests.get(devices_url, headers=headers, params=payload)
    assert response.status_code == 400
    response_boilerplate_checks(response)


def test_devices_preflight():
    response = requests.options(devices_url)
    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "GET" in response.headers["Access-Control-Allow-Methods"]
    assert "OPTIONS" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "7200"


# /devices/{device_guid}
print(f"-- Test URL = {devices_url}/{{device_guid}}")


def test_get_device_invalid_id():
    fake_url = devices_url + "/ABCD"
    response = requests.get(fake_url, headers=headers)
    assert response.status_code == 404
    response_boilerplate_checks(response)


def test_device_preflight():
    response = requests.options(devices_url + "/ABCD")
    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "GET" in response.headers["Access-Control-Allow-Methods"]
    assert "PATCH" in response.headers["Access-Control-Allow-Methods"]
    assert "DELETE" in response.headers["Access-Control-Allow-Methods"]
    assert "OPTIONS" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "7200"


# /devices/adopt
print(f"-- Test URL = {devices_url}/adopt")


def test_adopt_preflight():
    response = requests.options(adopt_url)
    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "POST" in response.headers["Access-Control-Allow-Methods"]
    assert "OPTIONS" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "7200"


# /devices/{device_guid}/state
print(f"-- Test URL = {devices_url}/{{device_guid}}/state")


def test_get_device_state_invalid_id():
    fake_url = devices_url + "/ABCD"
    response = requests.get(fake_url, headers=headers)
    assert response.status_code == 404
    response_boilerplate_checks(response)


def test_device_state_preflight():
    response = requests.options(devices_url + "/ABCD/state")
    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "GET" in response.headers["Access-Control-Allow-Methods"]
    assert "OPTIONS" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "7200"


# /devices/metrics
# /devices/{device_guid}/metrics
print(f"-- Test URL = {devices_url}/metrics and "
      f"alias {devices_url}/{{device_guid}}/metrics")


def test_devices_metrics_preflight():
    response = requests.options(devices_url + "/metrics")
    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "GET" in response.headers["Access-Control-Allow-Methods"]
    assert "POST" in response.headers["Access-Control-Allow-Methods"]
    assert "OPTIONS" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "7200"


def test_device_metrics_preflight():
    response = requests.options(devices_url + "/ABCD/metrics")
    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "POST" in response.headers["Access-Control-Allow-Methods"]
    assert "OPTIONS" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "7200"


def test_get_devices_metrics():
    response = requests.get(devices_url + "/metrics", headers=headers)
    assert response.status_code == 200
    response_boilerplate_checks(response)


def test_get_device_metrics():
    response = requests.get(devices_url + "/ABCD/metrics", headers=headers)
    assert response.status_code == 200
    response_boilerplate_checks(response)


# POST for device metrics is read-only
def test_post_devices_metrics():
    test_metrics = [{
        "namespace": "test",
        "metric_name": "test",
        "period": 60,
        "statistic": "Sum"
    }]

    body = {
        "start_time": "2022-02-21T12:45:00Z",
        "end_time": "2022-02-22T12:45:00Z",
        "metrics": test_metrics,
        "device_guids": ["ABCD"]
    }

    response = requests.post(devices_url + "/metrics",
                             json=body,
                             headers=headers)
    assert response.status_code == 200
    assert "metrics" in response.json()
    assert isinstance(response.json().get("metrics"), list)
    response_boilerplate_checks(response)

    del body["device_guids"]
    response = requests.post(devices_url + "/ABCD/metrics",
                             json=body,
                             headers=headers)
    assert response.status_code == 200
    assert "metrics" in response.json()
    assert isinstance(response.json().get("metrics"), list)
    response_boilerplate_checks(response)


def test_post_devices_metrics_time_range_validation():
    test_metrics = [{
        "namespace": "test",
        "metric_name": "test",
        "period": 60,
        "statistic": "Sum"
    }]

    # Invalid start time
    body = {
        "start_time": "abc",
        "end_time": "2022-02-22T12:45:00Z",
        "metrics": test_metrics,
        "device_guids": ["ABCD"]
    }

    response = requests.post(devices_url + "/metrics",
                             json=body,
                             headers=headers)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    response = requests.post(devices_url + "/ABCD/metrics",
                             json=body,
                             headers=headers)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    # Invalid end time
    body = {
        "start_time": "2022-02-22T12:45:00Z",
        "end_time": "abc",
        "metrics": test_metrics,
        "device_guids": ["ABCD"]
    }

    response = requests.post(devices_url + "/metrics",
                             json=body,
                             headers=headers)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    response = requests.post(devices_url + "/ABCD/metrics",
                             json=body,
                             headers=headers)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    # Start time must be greater than end time
    body = {
        "start_time": "2022-02-22T12:45:00Z",
        "end_time": "2022-02-21T12:45:00Z",
        "metrics": test_metrics,
        "device_guids": ["ABCD"]
    }

    response = requests.post(devices_url + "/metrics",
                             json=body,
                             headers=headers)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    response = requests.post(devices_url + "/ABCD/metrics",
                             json=body,
                             headers=headers)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    # Test other ISO formats
    body = {
        "start_time": "2022-02-21T12:45:00+03:00",
        "end_time": "2022-02-22T12:45:00-03:00",
        "metrics": test_metrics,
        "device_guids": ["ABCD"]
    }

    response = requests.post(devices_url + "/metrics",
                             json=body,
                             headers=headers)
    assert response.status_code == 200
    response_boilerplate_checks(response)

    response = requests.post(devices_url + "/ABCD/metrics",
                             json=body,
                             headers=headers)
    assert response.status_code == 200
    response_boilerplate_checks(response)


def test_post_devices_metrics_pagination_size_validation():
    test_metrics = [{
        "namespace": "test",
        "metric_name": "test",
        "period": 60,
        "statistic": "Sum"
    }]

    # Invalid start time
    body = {
        "start_time": "2022-02-21T12:45:00Z",
        "end_time": "2022-02-22T12:45:00Z",
        "metrics": test_metrics,
        "device_guids": ["ABCD"]
    }

    body["pagination_size"] = 0

    response = requests.post(devices_url + "/metrics",
                             json=body,
                             headers=headers)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    body["pagination_size"] = 61
    response = requests.post(devices_url + "/metrics",
                             json=body,
                             headers=headers)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    body["pagination_size"] = "abc"
    response = requests.post(devices_url + "/metrics",
                             json=body,
                             headers=headers)
    assert response.status_code == 400
    response_boilerplate_checks(response)


# /devices/events
# /devices/{device_guid}/events
print(f"-- Test URL = {devices_url}/events and "
      f"alias {devices_url}/{{device_guid}}/events")


def test_devices_events_preflight():
    response = requests.options(devices_url + "/events")
    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "GET" in response.headers["Access-Control-Allow-Methods"]
    assert "OPTIONS" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "7200"


def test_device_events_preflight():
    response = requests.options(devices_url + "/ABCD/events")
    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "GET" in response.headers["Access-Control-Allow-Methods"]
    assert "OPTIONS" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "7200"


def test_get_devices_events():
    payload = { "start_time": "2022-02-22T12:45:00Z",
                "device_guids": "ABCD" }
    response = requests.get(devices_url + "/events",
                            params=payload,
                            headers=headers)
    assert response.status_code == 200
    assert "events" in response.json()
    assert isinstance(response.json().get("events"), list)
    response_boilerplate_checks(response)

    response = requests.get(devices_url + "/ABCD/events", headers=headers)
    assert response.status_code == 200
    assert "events" in response.json()
    assert isinstance(response.json().get("events"), list)
    response_boilerplate_checks(response)


def test_get_devices_events_time_range_validation():
    # Invalid start time
    payload = {
        "start_time": "abc",
        "end_time": "2022-02-22T12:45:00Z",
        "device_guids": ["ABCD"]
    }

    response = requests.get(devices_url + "/events",
                            params=payload,
                            headers=headers)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    response = requests.get(devices_url + "/ABCD/events",
                            params=payload,
                            headers=headers)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    # Invalid end time
    payload = {
        "start_time": "2022-02-22T12:45:00Z",
        "end_time": "abc",
        "device_guids": ["ABCD"]
    }

    response = requests.get(devices_url + "/events",
                            params=payload,
                            headers=headers)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    response = requests.get(devices_url + "/ABCD/events",
                            params=payload,
                            headers=headers)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    # Start time must be greater than end time
    payload = {
        "start_time": "2022-02-22T12:45:00Z",
        "end_time": "2022-02-21T12:45:00Z",
        "device_guids": ["ABCD"]
    }

    response = requests.get(devices_url + "/events",
                            params=payload,
                            headers=headers)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    response = requests.get(devices_url + "/ABCD/events",
                            params=payload,
                            headers=headers)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    # Test other ISO formats
    payload = {
        "start_time": "2022-02-21T12:45:00+03:00",
        "end_time": "2022-02-22T12:45:00-03:00",
        "device_guids": ["ABCD"]
    }

    response = requests.get(devices_url + "/events",
                            params=payload,
                            headers=headers)
    assert response.status_code == 200
    response_boilerplate_checks(response)

    response = requests.get(devices_url + "/ABCD/events",
                            params=payload,
                            headers=headers)
    assert response.status_code == 200
    response_boilerplate_checks(response)


def test_get_devices_events_pagination_size_validation():
    payload = {
        "start_time": "2022-02-21T12:45:00Z",
        "end_time": "2022-02-22T12:45:00Z",
        "device_guids": ["ABCD"]
    }

    payload["pagination_size"] = 0

    response = requests.get(devices_url + "/events",
                            params=payload,
                            headers=headers)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    payload["pagination_size"] = 61
    response = requests.get(devices_url + "/events",
                            params=payload,
                            headers=headers)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    payload["pagination_size"] = "abc"
    response = requests.get(devices_url + "/events",
                            params=payload,
                            headers=headers)
    assert response.status_code == 400
    response_boilerplate_checks(response)
