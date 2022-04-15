"""API Read-Only Integration Tests (Fleets)

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

root_url = urljoin(api_gateway_url, "fleets")
print(f"-- Test URL = {root_url}")

headers = {"Authorization": test_account_auth}


def response_boilerplate_checks(response):
    """Check for standard fields that should be present in all of our
    responses.  Tests should call this function.
    """
    assert "operation_name" in response.json()
    assert len(response.json().get("operation_name")) > 4
    assert "api_request_id" in response.json()
    assert len(response.json().get("api_request_id")) == 36


# /fleets
def test_get_fleets():
    response = requests.get(root_url, headers=headers)
    assert response.status_code == 200
    assert "fleets" in response.json()
    assert isinstance(response.json().get("fleets"), list)
    response_boilerplate_checks(response)


def test_get_fleets_invalid_token():
    payload = {"pagination_token": "ABC"}
    response = requests.get(root_url, headers=headers, params=payload)
    assert response.status_code == 400
    assert "message" in response.json()
    response_boilerplate_checks(response)


def test_get_fleets_pagination_size_validation():
    payload = {"pagination_size": 0}
    response = requests.get(root_url, headers=headers, params=payload)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    payload = {"pagination_size": 61}
    response = requests.get(root_url, headers=headers, params=payload)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    payload = {"pagination_size": "abc"}
    response = requests.get(root_url, headers=headers, params=payload)
    assert response.status_code == 400
    response_boilerplate_checks(response)


def test_fleets_preflight():
    response = requests.options(root_url)
    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "GET" in response.headers["Access-Control-Allow-Methods"]
    assert "POST" in response.headers["Access-Control-Allow-Methods"]
    assert "OPTIONS" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "7200"


# /fleets/{fleet_guid}
print(f"-- Test URL = {root_url}/{{fleet_guid}}")
def test_get_device_invalid_id():
    fake_url = root_url + "/ABCD"
    response = requests.get(fake_url, headers=headers)
    assert response.status_code == 404
    response_boilerplate_checks(response)


def test_fleet_preflight():
    response = requests.options(root_url + "/ABCD")
    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "GET" in response.headers["Access-Control-Allow-Methods"]
    assert "PATCH" in response.headers["Access-Control-Allow-Methods"]
    assert "DELETE" in response.headers["Access-Control-Allow-Methods"]
    assert "OPTIONS" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "7200"


# /fleets/{fleet_guid}/users
print(f"-- Test URL = {root_url}/{{fleet_guid}}/users")
def test_users_preflight():
    response = requests.options(root_url + "/ABCD/users")
    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "GET" in response.headers["Access-Control-Allow-Methods"]
    assert "POST" in response.headers["Access-Control-Allow-Methods"]
    assert "PUT" in response.headers["Access-Control-Allow-Methods"]
    assert "DELETE" in response.headers["Access-Control-Allow-Methods"]
    assert "OPTIONS" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "7200"


# /fleets/{fleet_guid}/devices
print(f"-- Test URL = {root_url}/{{fleet_guid}}/devices")
def test_devices_preflight():
    response = requests.options(root_url + "/ABCD/devices")
    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "GET" in response.headers["Access-Control-Allow-Methods"]
    assert "POST" in response.headers["Access-Control-Allow-Methods"]
    assert "DELETE" in response.headers["Access-Control-Allow-Methods"]
    assert "OPTIONS" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "7200"


# /fleets/{fleet_guid}/events
print(f"-- Test URL = {root_url}/{{fleet_guid}}/events")
def test_fleets_events_preflight():
    response = requests.options(root_url + "/ABCD/events")
    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "GET" in response.headers["Access-Control-Allow-Methods"]
    assert "OPTIONS" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "7200"


def test_get_fleets_events():
    response = requests.get(root_url +
                            "/ABCD/events?start_time=2022-02-22T12:45:00Z",
                            headers=headers)
    assert response.status_code == 200
    assert "events" in response.json()
    assert isinstance(response.json().get("events"), list)
    response_boilerplate_checks(response)
