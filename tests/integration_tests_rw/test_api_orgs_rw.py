"""API Read-Write Integration Tests (Organizations)

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
import uuid

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


test_org_base = None
org_guids = []
num_test_orgs = 10


@pytest.mark.dependency()
def test_create_organizations():
    global test_org_base
    global org_guids
    global num_test_orgs

    # Generate a bunch of test orgs and verify they were created.
    # To avoid collisions with previous test runs, add a random id.
    random_id = "".join(
        random.choices(string.ascii_uppercase + string.digits, k=8))
    test_org_base = f"Test Organization {random_id}"

    print("Creating organizations...")

    for x in range(num_test_orgs):
        test_org_name = f"{test_org_base} {x:02d}"
        request_body = {"org_name": test_org_name}
        response = requests.post(test_url, json=request_body, headers=headers)
        assert response.status_code == 201
        assert "created successfully" in response.json().get("message")
        response_boilerplate_checks(response)

        org_guids.append(response.json().get("org_guid"))


@pytest.mark.dependency(depends=["test_create_organizations"])
def test_get_organizations():
    global org_guids
    global test_org_base

    print("Getting organizations...")
    for guid in org_guids:
        response = requests.get(urljoin(api_gateway_url, "orgs/" + guid),
                                headers=headers)
        assert response.status_code == 200
        assert response.json().get("org") is not None
        assert test_org_base in response.json()["org"].get("org_name")
        response_boilerplate_checks(response)


@pytest.mark.dependency(depends=["test_create_organizations"])
def test_update_organizations():
    global test_org_base
    global org_guids

    print("Updating organizations...")
    for x, guid in enumerate(org_guids):
        test_org_name = f"{test_org_base} 2 {x:02d}"
        response = requests.patch(urljoin(api_gateway_url, "orgs/" + guid),
                                  json={"org_name": test_org_name},
                                  headers=headers)
        assert response.status_code == 200
        assert response.json()["message"] == "Organization updated successfully"
        response_boilerplate_checks(response)


@pytest.mark.dependency(depends=["test_update_organizations"])
def test_get_organizations2():
    global test_org_base
    global org_guids

    print("Getting organizations (2)...")
    for guid in org_guids:
        response = requests.get(urljoin(api_gateway_url, "orgs/" + guid),
                                headers=headers)
        assert response.status_code == 200
        assert response.json().get("org") is not None
        assert f"{test_org_base} 2" in response.json()["org"].get("org_name")
        response_boilerplate_checks(response)


@pytest.mark.dependency(depends=["test_create_organizations"])
def test_custom_pagination():
    global num_test_orgs

    print("Checking customizable pagination...")
    pagination_size = int(num_test_orgs / 2)
    response = requests.get(urljoin(
        api_gateway_url, "orgs/?pagination_size=" + str(pagination_size)),
                            headers=headers)
    assert response.status_code == 200
    assert len(response.json()["orgs"]) == pagination_size
    response_boilerplate_checks(response)


@pytest.mark.dependency(depends=["test_custom_pagination"])
def test_custom_pagination2():
    global num_test_orgs

    print("Checking customizable pagination... (2)")
    pagination_size = int(num_test_orgs / 2) - 1
    if pagination_size > 0:
        response = requests.get(urljoin(
            api_gateway_url, "orgs/?pagination_size=" + str(pagination_size)),
                                headers=headers)
        assert response.status_code == 200
        assert len(response.json()["orgs"]) == pagination_size
        response_boilerplate_checks(response)


@pytest.mark.dependency(depends=["test_create_organizations"])
def test_get_orgs_events():
    global org_guids
    payload = {"start_time": "2022-02-22T12:45:00Z"}
    response = requests.get(test_url + f"/{org_guids[0]}/events",
                            params=payload,
                            headers=headers)
    assert response.status_code == 200
    assert "events" in response.json()
    assert isinstance(response.json().get("events"), list)
    response_boilerplate_checks(response)


@pytest.mark.dependency(depends=["test_create_organizations"])
def test_delete_organizations():
    print("Deleting organizations...")

    reason_obj = {"reason": "Unit Test Cleanup"}
    for guid in org_guids:
        response = requests.delete(urljoin(api_gateway_url, "orgs/" + guid),
                                   json=reason_obj,
                                   headers=headers)

        assert response.status_code == 200
        assert response.json()["message"] == "Organization successfully deleted"
        response_boilerplate_checks(response)


def test_get_fake_organization():
    print("Getting organization that doesn't exist...")
    fake_guid = str(uuid.uuid4())
    fake_url = urljoin(api_gateway_url, "orgs/" + fake_guid)
    response = requests.get(fake_url, headers=headers)
    assert response.status_code == 404
    response_boilerplate_checks(response)


def test_patch_fake_organization():
    print("Patching organization that doesn't exist...")
    fake_guid = str(uuid.uuid4())
    fake_url = urljoin(api_gateway_url, "orgs/" + fake_guid)
    response = requests.patch(fake_url,
                              json={"org_name": "I shouldn't be real"},
                              headers=headers)
    assert response.status_code == 404
    assert response.json()["message"] == "Organization not found"
    response_boilerplate_checks(response)


def test_delete_fake_organization():
    print("Delete organization that doesn't exist...")
    fake_guid = str(uuid.uuid4())
    fake_url = urljoin(api_gateway_url, "orgs/" + fake_guid)
    response = requests.delete(
        fake_url,
        json={"reason": "Unit Test Cleanup; Shouldn't Exist"},
        headers=headers)
    assert response.status_code == 404
    assert response.json()["message"] == "Organization not found"
    response_boilerplate_checks(response)


@pytest.mark.dependency()
def test_create_organizations_edge():
    global org_guids

    random_id = "".join(
        random.choices(string.ascii_uppercase + string.digits, k=8))
    org_base_edge = f"Test Organization {random_id}"

    org_guids = []

    print("Creating organizations...")
    for x in range(2):
        test_org_name = f"{org_base_edge} {x:02d}"
        request_body = {"org_name": test_org_name}
        response = requests.post(test_url, json=request_body, headers=headers)

        assert response.status_code == 201
        assert "created successfully" in response.json().get("message")
        response_boilerplate_checks(response)

        org_guids.append(response.json().get("org_guid"))


@pytest.mark.dependency(depends=["test_create_organizations_edge"])
def test_pagination_organizations_edge():
    print("Getting organizations with invalid pagination token...")
    response = requests.get(urljoin(api_gateway_url,
                                    "orgs/?pagination_token=null"),
                            headers=headers)
    assert response.status_code == 400
    assert "Invalid pagination token" in response.json()["message"]
    response_boilerplate_checks(response)

    print("Getting organizations with invalid pagination size...")
    response = requests.get(urljoin(api_gateway_url,
                                    "orgs/?pagination_size=INVALID_SIZE"),
                            headers=headers)
    assert response.status_code == 400
    assert "Invalid pagination size" in response.json()["message"]
    response_boilerplate_checks(response)


@pytest.mark.dependency(depends=["test_create_organizations_edge"])
def test_delete_organizations_edge():
    print("Deleting organizations with no reason...")
    for i, guid in enumerate(org_guids[0:2]):
        value = ("", "{}")[i]

        response = requests.delete(urljoin(api_gateway_url, "orgs/" + guid),
                                   data=value,
                                   headers=headers)

        assert response.status_code == 400
        response_boilerplate_checks(response)


@pytest.mark.dependency(depends=["test_create_organizations_edge"])
def test_cleanup_organizations_edge():
    print("Deleting organizations...")
    for guid in org_guids:
        reason_obj = {"reason": "Unit Test Cleanup"}
        response = requests.delete(urljoin(api_gateway_url, "orgs/" + guid),
                                   json=reason_obj,
                                   headers=headers)

        assert response.status_code == 200
        assert response.json()["message"] == "Organization successfully deleted"
        response_boilerplate_checks(response)
