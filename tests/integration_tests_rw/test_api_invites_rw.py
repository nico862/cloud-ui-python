"""API Read-Write Integration Tests (Invites)

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
test_email = os.environ["TEST_EMAIL"]
test_guid = os.environ["TEST_GUID"]

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


test_info = {"num_test_objects": 5, "org_guids": [], "invite_guids": []}


@pytest.mark.dependency()
def test_invites_setup():
    global test_info

    # Generate a bunch of test orgs
    # To avoid collisions with previous test runs, add a random id.
    random_id = "".join(
        random.choices(string.ascii_uppercase + string.digits, k=8))
    test_org_base = f"Test Organization {random_id}"

    print("Creating organizations to test inviting...")
    for x in range(test_info["num_test_objects"]):
        test_org_name = f"{test_org_base} {x:02d}"
        request_body = {"org_name": test_org_name}
        response = requests.post(urljoin(api_gateway_url, "orgs"),
                                 json=request_body,
                                 headers=headers)
        assert response.status_code == 201

        test_info["org_guids"].append(response.json().get("org_guid"))


@pytest.mark.dependency(depends=["test_invites_setup"])
def test_create_invite_invalid_access():
    global test_info

    request_body = {
        "org_guid": test_info["org_guids"][0],
        "target_email": test_email,
        "access": 5
    }
    response = requests.post(invites_url, headers=headers, json=request_body)

    assert response.status_code == 400
    response_boilerplate_checks(response)


@pytest.mark.dependency(depends=["test_invites_setup"])
def test_create_invite():
    global test_info

    for i in range(test_info["num_test_objects"]):
        request_body = {
            "org_guid": test_info["org_guids"][i],
            "target_email": test_email,
            "access": 100
        }
        response = requests.post(invites_url,
                                 headers=headers,
                                 json=request_body)

        assert response.status_code == 201
        response_boilerplate_checks(response)
        test_info["invite_guids"].append(response.json().get("invite_guid"))


@pytest.mark.dependency(depends=["test_create_invite"])
def test_get_invites():
    pagination_size = test_info["num_test_objects"] - 1
    payload = {"pagination_size": pagination_size}

    response = requests.get(invites_url, headers=headers, params=payload)
    assert response.status_code == 200
    response_boilerplate_checks(response)
    assert len(response.json().get("invites")) == pagination_size

    pagination_token = response.json().get("pagination_token")
    assert pagination_token is not None

    payload["pagination_token"] = pagination_token
    response = requests.get(invites_url, headers=headers, params=payload)
    assert response.status_code == 200
    response_boilerplate_checks(response)

    payload = {"org_guid": test_info["org_guids"][0]}
    response = requests.get(invites_url, headers=headers, params=payload)
    assert response.status_code == 200
    response_boilerplate_checks(response)
    assert len(response.json().get("invites")) == 1


@pytest.mark.dependency(depends=["test_create_invite"])
def test_accept_fake_invite():
    body = {"invite_guid": "abc"}
    response = requests.post(invites_accept_url, headers=headers, json=body)

    assert response.status_code == 404
    response_boilerplate_checks(response)


@pytest.mark.dependency(depends=["test_create_invite"])
def test_decline_fake_invite():
    body = {"invite_guid": "abc"}
    response = requests.post(invites_decline_url, headers=headers, json=body)

    assert response.status_code == 404
    response_boilerplate_checks(response)


@pytest.mark.dependency(depends=["test_create_invite"])
def test_accept_decline_setup():
    # Remove the test account from the organizations
    # before trying to accept or decline the invites
    for org_guid in test_info["org_guids"]:
        request_data = {"users": [test_guid]}
        endpoint = f"orgs/{org_guid}/users"
        response = requests.delete(urljoin(api_gateway_url, endpoint),
                                   json=request_data,
                                   headers=headers)
        assert response.status_code == 200


@pytest.mark.dependency(depends=["test_accept_decline_setup"])
def test_accept_invite():
    global test_info

    # Accept every other invite
    for i in range(0, test_info["num_test_objects"], 2):
        body = {"invite_guid": test_info["invite_guids"][i]}
        response = requests.post(invites_accept_url, headers=headers, json=body)

        assert response.status_code == 200
        response_boilerplate_checks(response)


@pytest.mark.dependency(depends=["test_accept_decline_setup"])
def test_decline_invite():
    global test_info

    # Decline every other invite (opposite of accepted ones)
    for i in range(1, test_info["num_test_objects"], 2):
        body = {"invite_guid": test_info["invite_guids"][i]}
        response = requests.post(invites_decline_url,
                                 headers=headers,
                                 json=body)

        assert response.status_code == 200
        response_boilerplate_checks(response)


@pytest.mark.dependency(depends=["test_invites_setup"])
def test_invites_cleanup():
    print("Deleting test organizations...")
    reason_obj = {"reason": "Unit Test Cleanup"}

    for guid in test_info["org_guids"]:
        requests.delete(urljoin(api_gateway_url, "orgs/" + guid),
                        json=reason_obj,
                        headers=headers)

    print("Deleting any invites that were not properly responded to...")
    for guid in test_info["invite_guids"]:
        requests.delete(urljoin(api_gateway_url, "invites/" + guid),
                        headers=headers)
