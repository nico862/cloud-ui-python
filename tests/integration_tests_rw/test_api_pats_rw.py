"""API Read-Write Integration Tests (Personal Access Tokens)

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
import string
import os

from urllib.parse import urljoin

api_gateway_url = os.environ["API_GATEWAY_URL"]
test_account_auth_type = os.environ["TEST_AUTH_TYPE"]
test_account_auth_token = os.environ["TEST_AUTH_TOKEN"]
test_account_auth = f"{test_account_auth_type} {test_account_auth_token}"

test_url = urljoin(api_gateway_url, "pats")
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


token_guids = []
test_token_base = None
num_test_tokens = 10


@pytest.mark.dependency()
def test_create_tokens():
    global token_guids
    global test_token_base
    global num_test_tokens

    # Generate a bunch of test pats and verify they were created.
    # To avoid collisions with previous test runs, add a random id.
    random_id = "".join(
        random.choices(string.ascii_uppercase + string.digits, k=8))
    test_token_base = f"Test PAT {random_id}"

    print("Creating personal access tokens...")

    for x in range(num_test_tokens):
        test_token_comment = f"{test_token_base} {x:02d}"
        request_body = {"token_lifespan_days": 5, "comment": test_token_comment}
        response = requests.post(test_url, json=request_body, headers=headers)
        assert response.status_code == 201
        assert "token_guid" in response.json()
        assert "token_prefix" in response.json()
        assert "token_value" in response.json()
        assert "expires" in response.json()
        response_boilerplate_checks(response)

        token_guids.append(response.json().get("token_guid"))


@pytest.mark.dependency(depends=["test_create_tokens"])
def test_get_tokens():
    global token_guids
    global test_token_base

    print("Getting personal access tokens...")
    for guid in token_guids:
        response = requests.get(urljoin(api_gateway_url, "pats/" + guid),
                                headers=headers)
        assert response.status_code == 200
        assert response.json().get("personal_access_token") is not None
        assert test_token_base in response.json()["personal_access_token"].get(
            "comment")
        response_boilerplate_checks(response)


@pytest.mark.dependency(depends=["test_create_tokens"])
def test_custom_pagination():
    global num_test_tokens

    print("Checking customizable pagination...")
    pagination_size = int(num_test_tokens / 2)
    response = requests.get(urljoin(
        api_gateway_url, "pats?pagination_size=" + str(pagination_size)),
                            headers=headers)
    assert response.status_code == 200
    assert len(response.json()["personal_access_tokens"]) <= pagination_size
    response_boilerplate_checks(response)


@pytest.mark.dependency(depends=["test_custom_pagination"])
def test_custom_pagination2():
    global num_test_tokens

    print("Checking customizable pagination... (2)")
    pagination_size = int(num_test_tokens / 2) - 1
    if pagination_size > 0:
        response = requests.get(urljoin(
            api_gateway_url, "pats?pagination_size=" + str(pagination_size)),
                                headers=headers)
        assert response.status_code == 200
        assert len(response.json()["personal_access_tokens"]) <= pagination_size
        response_boilerplate_checks(response)


@pytest.mark.dependency(depends=["test_create_tokens"])
def test_delete_tokens():
    global token_guids

    print("Deleting tokens...")

    for guid in token_guids:
        response = requests.delete(urljoin(api_gateway_url, "pats/" + guid),
                                   headers=headers)

        assert response.status_code == 200
        assert response.json()["message"] == "Token successfully revoked"
        response_boilerplate_checks(response)


def test_delete_invalid_token():
    print("Delete token that doesn't exist...")
    fake_guid = "ABCD"
    fake_url = urljoin(api_gateway_url, "pats/" + fake_guid)
    response = requests.delete(fake_url, headers=headers)
    assert response.status_code == 404
    assert response.json()["message"] == "Token not found"
    response_boilerplate_checks(response)
