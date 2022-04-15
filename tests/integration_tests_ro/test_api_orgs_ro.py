"""API Read-Only Integration Tests (Organizations)

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

test_url = urljoin(api_gateway_url, "orgs")
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


def test_find_organizations():
    # No parameters, should return all orgs.
    # Since these are R/O tests we cannot make any assumptions about how many
    # orgs are available to find.  Make sure the response looks valid.
    response = requests.get(test_url, headers=headers)
    assert response.status_code == 200
    assert "orgs" in response.json()
    assert isinstance(response.json().get("orgs"), list)
    assert "pagination_token" in response.json()
    response_boilerplate_checks(response)


def test_organizations_preflight():
    response = requests.options(test_url)
    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "GET" in response.headers["Access-Control-Allow-Methods"]
    assert "POST" in response.headers["Access-Control-Allow-Methods"]
    assert "OPTIONS" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "7200"


# /orgs/{org_guid}/events
print(f"-- Test URL = {test_url}/{{org_guid}}/events")
def test_orgs_events_preflight():
    response = requests.options(test_url + "/ABCD/events")
    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "GET" in response.headers["Access-Control-Allow-Methods"]
    assert "OPTIONS" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "7200"


def test_get_orgs_events():
    response = requests.get(test_url +
                            "/ABCD/events?start_time=2022-02-22T12:45:00Z",
                            headers=headers)
    assert response.status_code == 200
    assert "events" in response.json()
    assert isinstance(response.json().get("events"), list)
    response_boilerplate_checks(response)

