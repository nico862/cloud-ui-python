"""API Read-Only Integration Tests (Invites)

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

invites_url = urljoin(api_gateway_url, "invites")
invites_accept_url = urljoin(api_gateway_url, "invites/accept")
invites_decline_url = urljoin(api_gateway_url, "invites/decline")

print(f"-- Test URL = {invites_url}")

headers = {"Authorization": test_account_auth}


def response_boilerplate_checks(response):
    """Check for standard fields that should be present in all of our
    responses.  Tests should call this function.
    """
    assert "operation_name" in response.json()
    assert len(response.json().get("operation_name")) > 4
    assert "api_request_id" in response.json()
    assert len(response.json().get("api_request_id")) == 36


# /invites
def test_get_invites():
    response = requests.get(invites_url, headers=headers)
    assert response.status_code == 200
    assert "invites" in response.json()
    assert isinstance(response.json().get("invites"), list)
    response_boilerplate_checks(response)


def test_get_invites_invalid_token():
    payload = {"pagination_token": "ABC"}
    response = requests.get(invites_url, headers=headers, params=payload)
    assert response.status_code == 400
    assert "message" in response.json()
    response_boilerplate_checks(response)


def test_get_invites_pagination_size_validation():
    payload = {"pagination_size": 0}
    response = requests.get(invites_url, headers=headers, params=payload)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    payload = {"pagination_size": 61}
    response = requests.get(invites_url, headers=headers, params=payload)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    payload = {"pagination_size": "abc"}
    response = requests.get(invites_url, headers=headers, params=payload)
    assert response.status_code == 400
    response_boilerplate_checks(response)


def test_invites_preflight():
    response = requests.options(invites_url)
    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "GET" in response.headers["Access-Control-Allow-Methods"]
    assert "POST" in response.headers["Access-Control-Allow-Methods"]
    assert "OPTIONS" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "7200"


# /invites/{guid}
print(f"-- Test URL = {invites_url}/{{invite_guid}}")
def test_invites_guid_preflight():
    response = requests.options(invites_url + "/ABCD")
    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "GET" in response.headers["Access-Control-Allow-Methods"]
    assert "DELETE" in response.headers["Access-Control-Allow-Methods"]
    assert "OPTIONS" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "7200"


def test_get_invite():
    fake_url = invites_url + "/ABCD"
    response = requests.get(fake_url, headers=headers)
    assert response.status_code == 404
    response_boilerplate_checks(response)


# /invites/accept
print(f"-- Test URL = {invites_url}/accept")
def test_invites_accept_preflight():
    response = requests.options(invites_accept_url)
    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "POST" in response.headers["Access-Control-Allow-Methods"]
    assert "OPTIONS" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "7200"


# /invites/decline
print(f"-- Test URL = {invites_url}/decline")
def test_invites_decline_preflight():
    response = requests.options(invites_decline_url)
    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "POST" in response.headers["Access-Control-Allow-Methods"]
    assert "OPTIONS" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "7200"
