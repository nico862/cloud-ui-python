"""API Read-Write Integration Tests (Users/GUID)

These tests should be run against deployed code, typically as part of a
CI/CD pipeline.

Expects the API_GATEWAY_URL environment variable to be populated with the full
URL of the API Gateway, including the stage name.
(e.g. https://api.example.com/v1/)

Read-write tests may modify the application state (e.g. inserting test data),
but they should ONLY be used against non-production environments.
"""
import pytest

import random
import requests
import os

from urllib.parse import urljoin

api_gateway_url = os.environ["API_GATEWAY_URL"]
test_account_auth_type = os.environ["TEST_AUTH_TYPE"]
test_account_auth_token = os.environ["TEST_AUTH_TOKEN"]
test_account_auth = f"{test_account_auth_type} {test_account_auth_token}"

print(f"-- Test URL = {api_gateway_url}")

headers = {"Authorization": test_account_auth}


def response_boilerplate_checks(response):
    """Check for standard fields that should be present in all of our
    responses.  Tests should call this function.
    """
    assert "operation_name" in response.json()
    assert len(response.json().get("operation_name")) > 4
    assert "api_request_id" in response.json()
    assert len(response.json().get("api_request_id")) == 36


user_guids = []


@pytest.mark.dependency()
def test_create_user():
    global user_guids

    user_id = str(random.randint(0, 99999)).ljust(5, "0")

    num_test_users = 10
    for i in range(num_test_users):
        request_body = {
            "name":
                "Totally A Human {} {}".format(user_id, i),
            "email":
                "success+user{}-{}@simulator.amazonses.com".format(user_id, i),
            "password":
                "SecurePassword{}".format(user_id),
            "locale":
                "en-US",
            "zoneinfo":
                "America/New_York (GMT-05:00)"
        }

        response = requests.post(urljoin(api_gateway_url, "users"),
                                 json=request_body,
                                 headers=headers)

        if response.status_code != 201:
            print(response.json())

        assert response.status_code == 201
        assert "created successfully" in response.json().get("message")
        response_boilerplate_checks(response)

        response_json = response.json()
        user_guids.append(response_json["user_guid"])

        print(response_json["user_guid"])


@pytest.mark.dependency(depends=["test_create_user"])
def test_get_users():
    global user_guids

    for user in user_guids:
        response = requests.get(urljoin(api_gateway_url, "users/" + user),
                                headers=headers)
        assert response.status_code == 200
        assert response.json().get("user") is not None
        assert "Totally A Human" in response.json()["user"].get("name")


@pytest.mark.dependency(depends=["test_create_user"])
def test_search_users():
    response1 = requests.get(urljoin(
        api_gateway_url,
        "users?search_attribute=enabled&search_value=true&pagination_size=5"),
                             headers=headers)
    assert response1.status_code == 200
    assert len(response1.json()["users"]) == 5
    pagination_token = response1.json().get("pagination_token")
    assert pagination_token is not None

    payload = {
        "search_attribute": "enabled",
        "search_value": "true",
        "pagination_token": pagination_token,
        "pagination_size": 5
    }
    response2 = requests.get(urljoin(api_gateway_url, "users"),
                             params=payload,
                             headers=headers)
    assert response2.status_code == 200
    assert len(response1.json()["users"]) >= 1


@pytest.mark.dependency(depends=["test_create_user"])
def test_delete_users():
    global user_guids

    reason = {"reason": "Unit Test Cleanup"}

    for user in user_guids:
        response = requests.delete(urljoin(api_gateway_url, "users/" + user),
                                   json=reason,
                                   headers=headers)

        assert response.status_code == 200
