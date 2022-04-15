"""API Read-Write Integration Tests (Organization Membership)

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

test_url = urljoin(api_gateway_url, "orgs")
print(f"-- Test URL = {test_url}")

headers = {"Authorization": test_account_auth}

organization_guid = None
organization_base_url = None
user_guids = []


@pytest.mark.dependency()
def test_membership_setup():
    global organization_guid
    global organization_base_url
    global user_guids

    # Generate a bunch of test orgs and verify they were created.
    # To avoid collisions with previous test runs, add a random id.
    random_id = "".join(
        random.choices(string.ascii_uppercase + string.digits, k=8))
    test_org_name = f"Test Organization Membership {random_id}"

    print("Creating organization...")
    request_body = {"org_name": test_org_name}
    response = requests.post(test_url, json=request_body, headers=headers)
    assert response.status_code == 201
    assert "created successfully" in response.json()["message"]
    assert "org_guid" in response.json()

    organization_guid = response.json()["org_guid"]
    organization_base_url = urljoin(api_gateway_url,
                                    "orgs/{}/users".format(organization_guid))

    print("Creating users...")
    user_guids = []
    user_id = str(random.randint(0, 99999)).ljust(5, "0")

    num_users = 2
    for i in range(num_users):
        request_body = {
            "name":
                "Membership User {} {}".format(user_id, i),
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
        assert response.status_code == 201
        assert "created successfully" in response.json()["message"]

        user_guids.append(response.json()["user_guid"])


@pytest.mark.dependency(depends=["test_membership_setup"])
def test_membership_add():
    global user_guids

    print("Adding users...")
    access_levels = [300, 100]

    for i, user in enumerate(user_guids):
        request_data = {"user_guid": user, "access": access_levels[i]}

        response = requests.post(organization_base_url,
                                 json=request_data,
                                 headers=headers)
        assert response.status_code == 200


@pytest.mark.dependency(depends=["test_membership_add"])
def test_membership_get():
    global organization_base_url

    print("Getting users...")
    response = requests.get(organization_base_url, headers=headers)
    assert response.status_code == 200
    assert "users" in response.json()
    # Should be all of the users we added, plus ourselves
    assert len(response.json()["users"]) == (len(user_guids) + 1)

    access_levels = [user["access"] for user in response.json()["users"]]
    access_levels.sort()

    assert access_levels == [100, 300, 300]


@pytest.mark.dependency(depends=["test_membership_add"])
def test_membership_update():
    print("Updating users...")
    request_data = {"users": [{"user_guid": user_guids[1], "access": 200}]}
    response = requests.put(organization_base_url,
                            json=request_data,
                            headers=headers)
    assert response.status_code == 200


@pytest.mark.dependency(depends=["test_membership_update"])
def test_membership_get2():
    print("Getting users (2)...")
    response = requests.get(organization_base_url, headers=headers)
    assert response.status_code == 200
    assert "users" in response.json()
    # Should be all of the users we added, plus ourselves
    assert len(response.json()["users"]) == (len(user_guids) + 1)

    access_levels = [user["access"] for user in response.json()["users"]]
    access_levels.sort()

    assert access_levels == [200, 300, 300]


@pytest.mark.dependency(depends=["test_membership_setup"])
def test_membership_cleanup():
    print("Deleting users and organization...")
    reason = {"reason": "Unit Test Cleanup"}
    for user in user_guids:
        response = requests.delete(urljoin(api_gateway_url,
                                           "users/{}".format(user)),
                                   json=reason,
                                   headers=headers)

        assert response.status_code == 200

    reason = {"reason": "Unit Test Cleanup"}
    response = requests.delete(urljoin(api_gateway_url,
                                       "orgs/{}".format(organization_guid)),
                               json=reason,
                               headers=headers)

    assert response.status_code == 200
