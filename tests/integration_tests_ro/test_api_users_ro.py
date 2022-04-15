"""API Read-Only Integration Tests (Users)

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

test_url = urljoin(api_gateway_url, "users")
print(f"-- Test URL = {test_url}")

headers = {"Authorization": test_account_auth}


def response_boilerplate_checks(response):
    """Check for standard fields that should be present in all of our
    responses.  Tests should call this function.
    """
    assert "operation_name" in response.json()
    assert len(response.json().get("operation_name")) > 4
    assert "api_request_id" in response.json()
    assert len(response.json().get("api_request_id")) == 36


def test_find_users_authorizer():
    # Test that the authorizer is attached to the path.
    # No auth header should return 401.
    # Bogus auth headers should return 403.
    # We will validate the authorizer itself thoroughly elsewhere.
    response = requests.get(test_url)
    assert response.status_code == 401
    bogus_headers = {"Authorization": "Bogus Test"}
    response = requests.get(test_url, headers=bogus_headers)
    assert response.status_code == 403


def test_find_users_missing_all_params():
    response = requests.get(test_url, headers=headers)
    # Should return 400 and a properly-formatted JSON error message.
    print(f"-- Response = {response.json()}")
    assert response.json().get("message") is not None
    assert "Missing required request parameters" in \
        response.json().get("message")
    assert response.status_code == 400


def test_find_users_missing_search_attribute():
    payload = {"search_value": "test", "starts_with": "false"}
    response = requests.get(test_url, headers=headers, params=payload)
    # Should return 400 and a JSON error message about the missing param.
    assert "Missing required request parameters: [search_attribute]" in \
        response.json().get("message")
    assert response.status_code == 400


def test_find_users_missing_search_value():
    payload = {"search_attribute": "name", "starts_with": "false"}
    response = requests.get(test_url, headers=headers, params=payload)
    # Should return 400 and a JSON error message about the missing param.
    assert "Missing required request parameters: [search_value]" in \
        response.json().get("message")
    assert response.status_code == 400


def test_find_users_starts_with_optional():
    # Optional parameter.
    # Should return 200 and a properly-formatted JSON response.
    # Don't care about the specific results
    payload = {"search_attribute": "name", "search_value": "test"}
    response = requests.get(test_url, headers=headers, params=payload)
    assert "users" in response.json()
    assert response.json().get("operation_name") == "FindUsers"
    assert response.status_code == 200
    # Test both ways, with and without
    payload = {
        "search_attribute": "name",
        "search_value": "test",
        "starts_with": "false"
    }
    response = requests.get(test_url, headers=headers, params=payload)
    assert "users" in response.json()
    assert response.json().get("operation_name") == "FindUsers"
    assert response.status_code == 200


def test_find_users_starts_with_boolean():
    # Should accept boolean values, case insensitive.
    # Error on non-boolean.
    payload = {
        "search_attribute": "name",
        "search_value": "test",
        "starts_with": "false"
    }
    response = requests.get(test_url, headers=headers, params=payload)
    assert "users" in response.json()
    assert response.status_code == 200
    payload = {
        "search_attribute": "name",
        "search_value": "test",
        "starts_with": "true"
    }
    response = requests.get(test_url, headers=headers, params=payload)
    assert "users" in response.json()
    assert response.status_code == 200
    payload = {
        "search_attribute": "name",
        "search_value": "test",
        "starts_with": "TRUE"
    }
    response = requests.get(test_url, headers=headers, params=payload)
    assert "users" in response.json()
    assert response.status_code == 200
    payload = {
        "search_attribute": "name",
        "search_value": "test",
        "starts_with": "True"
    }
    response = requests.get(test_url, headers=headers, params=payload)
    assert "users" in response.json()
    assert response.status_code == 200
    payload = {
        "search_attribute": "name",
        "search_value": "test",
        "starts_with": "bacon"
    }
    response = requests.get(test_url, headers=headers, params=payload)
    assert "starts_with" in response.json().get("message")
    assert response.status_code == 400


def test_users_preflight():
    response = requests.options(test_url)
    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "GET" in response.headers["Access-Control-Allow-Methods"]
    assert "POST" in response.headers["Access-Control-Allow-Methods"]
    assert "OPTIONS" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "7200"
