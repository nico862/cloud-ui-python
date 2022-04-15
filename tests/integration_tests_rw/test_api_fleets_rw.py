"""API Read-Write Integration Tests (Fleets)

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
test_guid = os.environ["TEST_GUID"]

fleets_url = urljoin(api_gateway_url, "fleets")
print(f"-- Test URL = {fleets_url}")

headers = {"Authorization": test_account_auth}

test_info = {
    "num_test_objects": 2,
    "org_guids": [],
    "user_guids": [],
    "fleet_guids": []
}


def response_boilerplate_checks(response):
    """Check for standard fields that should be present in all of our
    responses.  Tests should call this function.
    """
    assert "operation_name" in response.json()
    assert len(response.json().get("operation_name")) > 4
    assert "api_request_id" in response.json()
    assert len(response.json().get("api_request_id")) == 36


@pytest.mark.dependency()
def test_fleets_setup():
    global test_info

    # Generate a test orgs and users
    # To avoid collisions with previous test runs, add a random id.
    random_id = "".join(
        random.choices(string.ascii_uppercase + string.digits, k=8))
    test_org_base = f"Test Organization {random_id}"

    print("Creating organizations and users to test fleets...")
    for x in range(test_info["num_test_objects"]):
        test_org_name = f"{test_org_base} {x:02d}"
        request_body = {"org_name": test_org_name}
        orgs_response = requests.post(urljoin(api_gateway_url, "orgs"),
                                      json=request_body,
                                      headers=headers)
        assert orgs_response.status_code == 201

        user_id = str(random.randint(0, 99999)).ljust(5, "0")
        request_body = {
            "name":
                "Membership User {} {}".format(user_id, x),
            "email":
                "success+user{}-{}@simulator.amazonses.com".format(user_id, x),
            "password":
                "SecurePassword{}".format(user_id),
            "locale":
                "en-US",
            "zoneinfo":
                "America/New_York (GMT-05:00)"
        }

        users_response = requests.post(urljoin(api_gateway_url, "users"),
                                       json=request_body,
                                       headers=headers)
        assert users_response.status_code == 201

        # Add user to org
        org_guid = orgs_response.json().get("org_guid")
        user_guid = users_response.json().get("user_guid")
        request_body = {"user_guid": user_guid, "access": 100}
        response = requests.post(urljoin(api_gateway_url,
                                         f"orgs/{org_guid}/users"),
                                 json=request_body,
                                 headers=headers)
        assert response.status_code in [200, 201]

        test_info["org_guids"].append(org_guid)
        test_info["user_guids"].append(user_guid)


@pytest.mark.dependency(depends=["test_fleets_setup"])
def test_create_fleets():
    print("Testing creating fleets...")

    global test_info
    random_id = "".join(
        random.choices(string.ascii_uppercase + string.digits, k=8))
    test_fleet_base = f"Test Fleet {random_id}"

    # Create multiple fleets for org 1 so pagination can be tested later
    org_1_fleets = []
    for x in range(1, 5):
        test_fleet_name = f"Org 1: {test_fleet_base} {x:02d}"
        request_body = {
            "fleet_name": test_fleet_name,
            "org_guid": test_info["org_guids"][0]
        }
        fleets_response = requests.post(fleets_url,
                                        json=request_body,
                                        headers=headers)
        assert fleets_response.status_code == 201
        assert "fleet_guid" in fleets_response.json()
        response_boilerplate_checks(fleets_response)
        org_1_fleets.append(fleets_response.json()["fleet_guid"])

    test_info["fleet_guids"].append(org_1_fleets)
    print(test_info["fleet_guids"])

    for x in range(1, test_info["num_test_objects"]):
        test_fleet_name = f"{test_fleet_base} {x:02d}"
        request_body = {
            "fleet_name": test_fleet_name,
            "org_guid": test_info["org_guids"][x]
        }
        fleets_response = requests.post(fleets_url,
                                        json=request_body,
                                        headers=headers)
        assert fleets_response.status_code == 201
        assert "fleet_guid" in fleets_response.json()
        response_boilerplate_checks(fleets_response)

        test_info["fleet_guids"].append(fleets_response.json()["fleet_guid"])


@pytest.mark.dependency(depends=["test_create_fleets"])
def test_get_fleets_org():
    print("Testing getting org's fleets...")

    global test_info
    for x in range(test_info["num_test_objects"]):
        payload = {"org_guid": test_info["org_guids"][x]}
        fleets_response = requests.get(fleets_url,
                                       params=payload,
                                       headers=headers)
        assert fleets_response.status_code == 200
        assert "fleets" in fleets_response.json()
        fleets = fleets_response.json().get("fleets")
        assert isinstance(fleets, list)
        response_boilerplate_checks(fleets_response)

        if x != 0:
            assert len(fleets) == 1


@pytest.mark.dependency(depends=["test_create_fleets"])
def test_get_fleets_org_pagination():
    print("Testing GET /fleets pagination...")

    global test_info

    payload = {"pagination_size": 1, "org_guid": test_info["org_guids"][0]}
    total_found = 0

    for x in test_info["fleet_guids"][0]:  # pylint: disable=unused-variable
        fleets_response = requests.get(fleets_url,
                                       params=payload,
                                       headers=headers)
        assert fleets_response.status_code == 200
        assert "fleets" in fleets_response.json()
        fleets = fleets_response.json().get("fleets")

        assert isinstance(fleets, list)
        assert len(fleets) == 1
        total_found += 1

        response_boilerplate_checks(fleets_response)

        pagination_token = fleets_response.json().get("pagination_token")
        payload["pagination_token"] = pagination_token

        if pagination_token is None:
            assert total_found == len(test_info["fleet_guids"][0])


@pytest.mark.dependency(depends=["test_create_fleets"])
def test_get_fleets_user():
    print("Testing getting own user's fleets...")

    payload = {"user_guid": test_guid}
    fleets_response = requests.get(fleets_url, params=payload, headers=headers)
    assert fleets_response.status_code == 200
    assert "fleets" in fleets_response.json()
    fleets = fleets_response.json().get("fleets")
    assert isinstance(fleets, list)
    response_boilerplate_checks(fleets_response)

    assert len(fleets) == 0


@pytest.mark.dependency(depends=["test_create_fleets"])
def test_get_fleets_other_user():
    print("Testing getting another user's fleets...")

    global test_info

    payload = {"user_guid": test_info["user_guids"][0]}
    fleets_response = requests.get(fleets_url, params=payload, headers=headers)
    assert fleets_response.status_code == 403
    response_boilerplate_checks(fleets_response)


# /fleets/{fleet_guid}
@pytest.mark.dependency(depends=["test_create_fleets"])
def test_get_fleet():
    print("Testing getting fleets by GUID...")

    global test_info

    for fleet in test_info["fleet_guids"][0]:
        fleets_response = requests.get(fleets_url + f"/{fleet}",
                                       headers=headers)
        assert fleets_response.status_code == 200
        assert "fleet" in fleets_response.json()
        fleet = fleets_response.json().get("fleet")
        assert "fleet_name" in fleet
        response_boilerplate_checks(fleets_response)


@pytest.mark.dependency(depends=["test_create_fleets"])
def test_update_fleet():
    print("Testing renaming fleets...")

    global test_info

    body = {"fleet_name": "Org 1: Testing Fleet Renaming"}
    for fleet in test_info["fleet_guids"][0]:
        fleets_response = requests.patch(fleets_url + f"/{fleet}",
                                         headers=headers,
                                         json=body)
        assert fleets_response.status_code == 200
        response_boilerplate_checks(fleets_response)


@pytest.mark.dependency(depends=["test_create_fleets"])
def test_delete_fleet():
    print("Testing deleting fleets...")

    global test_info

    body = {"reason": "Unit testing"}
    for fleet in test_info["fleet_guids"][0]:
        fleets_response = requests.delete(fleets_url + f"/{fleet}",
                                          headers=headers,
                                          json=body)
        assert fleets_response.status_code == 200
        response_boilerplate_checks(fleets_response)

    test_info["fleet_guids"][0] = []


# /fleets/{fleet_guid}/events
@pytest.mark.dependency(depends=["test_create_fleets"])
def test_get_fleets_events():
    global test_info
    payload = {"start_time": "2022-02-22T12:45:00Z"}
    response = requests.get(fleets_url +
                            f"/{test_info['fleet_guids'][0]}/events",
                            params=payload,
                            headers=headers)
    assert response.status_code == 200
    assert "events" in response.json()
    assert isinstance(response.json().get("events"), list)
    response_boilerplate_checks(response)


# /fleets/{fleet_guid}/users
@pytest.mark.dependency(depends=["test_create_fleets"])
def test_add_fleet_users():
    print("Testing adding users to fleet...")

    global test_info

    # Try adding user whose org is in fleet
    body = {"user_guid": test_info["user_guids"][1], "access": 100}
    fleet = test_info["fleet_guids"][1]
    fleets_response = requests.post(fleets_url + f"/{fleet}/users",
                                    headers=headers,
                                    json=body)
    assert fleets_response.status_code == 409
    response_boilerplate_checks(fleets_response)

    # Try adding user whose org is not in fleet
    body = {"user_guid": test_info["user_guids"][0], "access": 100}
    fleet = test_info["fleet_guids"][1]
    fleets_response = requests.post(fleets_url + f"/{fleet}/users",
                                    headers=headers,
                                    json=body)
    assert fleets_response.status_code == 200
    response_boilerplate_checks(fleets_response)

    # Try adding user already in fleet
    body = {"user_guid": test_info["user_guids"][0], "access": 100}
    fleet = test_info["fleet_guids"][1]
    fleets_response = requests.post(fleets_url + f"/{fleet}/users",
                                    headers=headers,
                                    json=body)
    assert fleets_response.status_code == 409
    response_boilerplate_checks(fleets_response)


@pytest.mark.dependency(depends=["test_create_fleets"])
def test_add_fleet_users_access_param_validation():
    print("Testing access level validation...")

    global test_info

    body = {"user_guid": test_info["user_guids"][0], "access": 101}
    fleet = test_info["fleet_guids"][1]
    fleets_response = requests.post(fleets_url + f"/{fleet}/users",
                                    headers=headers,
                                    json=body)
    assert fleets_response.status_code == 400
    response_boilerplate_checks(fleets_response)

    body = {"user_guid": test_info["user_guids"][0], "access": 0}
    fleet = test_info["fleet_guids"][1]
    fleets_response = requests.post(fleets_url + f"/{fleet}/users",
                                    headers=headers,
                                    json=body)
    assert fleets_response.status_code == 400
    response_boilerplate_checks(fleets_response)

    body = {"user_guid": test_info["user_guids"][0], "access": "abc"}
    fleet = test_info["fleet_guids"][1]
    fleets_response = requests.post(fleets_url + f"/{fleet}/users",
                                    headers=headers,
                                    json=body)
    assert fleets_response.status_code == 400
    response_boilerplate_checks(fleets_response)

    body = {"user_guid": test_info["user_guids"][0]}
    fleet = test_info["fleet_guids"][1]
    fleets_response = requests.post(fleets_url + f"/{fleet}/users",
                                    headers=headers,
                                    json=body)
    assert fleets_response.status_code == 400
    response_boilerplate_checks(fleets_response)


@pytest.mark.dependency(depends=["test_add_fleet_users"])
def test_update_fleet_users():
    print("Testing updating user fleet access...")

    global test_info

    body = {
        "users": [{
            "user_guid": test_info["user_guids"][0],
            "access": 300
        }, {
            "user_guid": test_info["user_guids"][1],
            "access": 300
        }]
    }
    fleet = test_info["fleet_guids"][1]
    fleets_response = requests.put(fleets_url + f"/{fleet}/users",
                                   headers=headers,
                                   json=body)
    assert fleets_response.status_code == 200
    assert "message" in fleets_response.json()
    assert "failed_users" in fleets_response.json()

    failed_users = fleets_response.json()["failed_users"]
    assert len(failed_users) == 1
    assert failed_users[0]["user_guid"] == test_info["user_guids"][1]

    response_boilerplate_checks(fleets_response)

    # Verify updated access
    payload = {"user_guid": test_info["user_guids"][0]}
    fleets_response = requests.get(fleets_url + f"/{fleet}/users",
                                   headers=headers,
                                   params=payload)
    assert fleets_response.status_code == 200
    assert "users" in fleets_response.json()

    users = fleets_response.json()["users"]
    assert len(users) == 1
    assert users[0]["access"] == 300

    response_boilerplate_checks(fleets_response)


@pytest.mark.dependency(depends=["test_add_fleet_users"])
def test_delete_fleet_users():
    print("Testing deleting users from fleet...")

    global test_info

    user_list = [test_info["user_guids"][0], test_info["user_guids"][1]]
    body = {"users": user_list}
    fleet = test_info["fleet_guids"][1]
    fleets_response = requests.delete(fleets_url + f"/{fleet}/users",
                                      headers=headers,
                                      json=body)
    assert fleets_response.status_code == 200
    assert "message" in fleets_response.json()
    assert "failed_users" in fleets_response.json()

    failed_users = fleets_response.json()["failed_users"]
    assert len(failed_users) == 1
    assert failed_users[0]["user_guid"] == test_info["user_guids"][1]

    response_boilerplate_checks(fleets_response)

    # Verify deleted user
    payload = {"user_guid": test_info["user_guids"][0]}
    fleets_response = requests.get(fleets_url + f"/{fleet}/users",
                                   headers=headers,
                                   params=payload)
    assert fleets_response.status_code == 200
    assert "users" in fleets_response.json()

    users = fleets_response.json()["users"]
    assert not users

    response_boilerplate_checks(fleets_response)


# TODO: /fleets/{fleet_guid}/devices testing


@pytest.mark.dependency(depends=["test_fleets_setup"])
def test_fleets_teardown():
    global test_info

    body = {"reason": "Unit test cleanup"}
    print("Deleting all organizations, users, and fleets created by tests...")
    for guid in test_info["org_guids"]:
        requests.delete(urljoin(api_gateway_url, "orgs/" + guid),
                        json=body,
                        headers=headers)

    for guid in test_info["user_guids"]:
        requests.delete(urljoin(api_gateway_url, "users/" + guid),
                        json=body,
                        headers=headers)

    for guid in test_info["fleet_guids"]:
        if isinstance(guid, list):
            for x in guid:
                requests.delete(urljoin(api_gateway_url, "fleets/" + x),
                                json=body,
                                headers=headers)
        else:
            requests.delete(urljoin(api_gateway_url, "fleets/" + guid),
                            json=body,
                            headers=headers)
