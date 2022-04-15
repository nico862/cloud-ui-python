"""API Read-Only Integration Tests (top-level)

Based on the examples here:
https://www.wwt.com/article/rest-api-integration-testing-using-python

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

_headers = {"Authorization": test_account_auth}
# HTTP header names should be case-insensitive.
_headers_lower = {"authorization": test_account_auth}


def response_boilerplate_checks(response):
    """Check for standard fields that should be present in all of our
    responses.  Tests should call this function.
    """
    assert "operation_name" in response.json()
    assert len(response.json().get("operation_name")) > 4
    assert "api_request_id" in response.json()
    assert len(response.json().get("api_request_id")) == 36


def test_authorizer():
    test_url = urljoin(api_gateway_url, "test-auth")
    print(f"-- Test URL = {test_url}")
    # Test the authorizer under a variety of authentication scenarios.
    response = requests.get(test_url)
    assert response.status_code == 401
    response = requests.get(test_url, headers=_headers)
    assert response.status_code == 200
    response = requests.get(test_url, headers=_headers_lower)
    assert response.status_code == 200
    bogus_headers = {"Authorization": "Bogus Test"}
    response = requests.get(test_url, headers=bogus_headers)
    assert response.status_code == 403


def test_nonexistant_path():
    test_url = urljoin(api_gateway_url, "some/nonexistant/path")
    print(f"-- Test URL = {test_url}")
    response = requests.get(test_url, headers=_headers)
    assert response.status_code == 404


def test_options_method():
    test_url = urljoin(api_gateway_url, "test-auth")
    print(f"-- Test URL = {test_url}")
    response = requests.options(test_url)
    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "GET" in response.headers["Access-Control-Allow-Methods"]
    assert "OPTIONS" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "7200"
