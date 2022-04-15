"""API Read-Only Integration Tests (Provisioning)

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

authorize_url = urljoin(api_gateway_url, "provisioning/authorize")
request_url = urljoin(api_gateway_url, "provisioning/request")


def response_boilerplate_checks(response):
    """Check for standard fields that should be present in all of our
    responses.  Tests should call this function.
    """
    assert "operation_name" in response.json()
    assert len(response.json().get("operation_name")) > 4
    assert "api_request_id" in response.json()
    assert len(response.json().get("api_request_id")) == 36


# /provisioning/authorize
print(f"-- Test URL = {authorize_url}")


def test_devices_preflight():
    response = requests.options(authorize_url)
    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "POST" in response.headers["Access-Control-Allow-Methods"]
    assert "OPTIONS" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "7200"


# /provisioning/request
print(f"-- Test URL = {request_url}")


def test_device_preflight():
    response = requests.options(request_url)
    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "POST" in response.headers["Access-Control-Allow-Methods"]
    assert "OPTIONS" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "7200"
