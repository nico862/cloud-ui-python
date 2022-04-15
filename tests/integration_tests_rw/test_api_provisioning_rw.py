"""API Read-Write Integration Tests (Provisioning)

These tests should be run against deployed code, typically as part of a
CI/CD pipeline.

Expects the API_GATEWAY_URL environment variable to be populated with the full
URL of the API Gateway, including the stage name.
(e.g. https://api.example.com/v1/)

Read-write tests may modify the application state (e.g. inserting test data),
but they should ONLY be used against non-production environments.
"""
import pytest

import requests
import os

from urllib.parse import urljoin

api_gateway_url = os.environ["API_GATEWAY_URL"]

authorize_url = urljoin(api_gateway_url, "provisioning/authorize")
request_url = urljoin(api_gateway_url, "provisioning/request")


def response_boilerplate_checks(response):
    """Check for standard fields that should be present in all of our
    JSON responses.  Tests should call this function.
    """
    assert "operation_name" in response.json()
    assert len(response.json().get("operation_name")) > 4
    assert "api_request_id" in response.json()
    assert len(response.json().get("api_request_id")) == 36


def binary_response_boilerplate_checks(response):
    """Check for standard fields that should be present in all of our
    binary responses.  Tests should call this function.
    """
    assert isinstance(response.content, (bytes, bytearray))


test_info = {
    "serial_number": "4730-0000",
    "mac_address": "00:25:4C:00:00:00",
    "provisioning_token": None
}


@pytest.mark.dependency()
def test_create_validation():
    # Invalid Serial Number
    request_body = {"serial_number": "4717", "mac_address": "D9:18:C8:8B:28:D1"}
    response = requests.post(authorize_url, json=request_body)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    request_body["serial_number"] = "1234-5678"
    response = requests.post(authorize_url, json=request_body)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    # Invalid Mac Address
    request_body["serial_number"] = "4717-0000"
    response = requests.post(authorize_url, json=request_body)
    assert response.status_code == 400
    response_boilerplate_checks(response)

    request_body["mac_address"] = "D9:18:C8:8B:28"
    response = requests.post(authorize_url, json=request_body)
    assert response.status_code == 400
    response_boilerplate_checks(response)


@pytest.mark.dependency()
def test_create_provisioning_request():
    global test_info

    request_body = {
        "serial_number": test_info["serial_number"],
        "mac_address": test_info["mac_address"]
    }
    response = requests.post(authorize_url, json=request_body)
    assert response.status_code == 201
    response_boilerplate_checks(response)

    test_info["provisioning_token"] = response.json()["provisioning_token"]


@pytest.mark.dependency()
def test_nonexistent_provisioning_request():
    global test_info

    request_body = {
        "serial_number": test_info["serial_number"],
        "mac_address": test_info["mac_address"],
        "provisioning_token": "abcdefg"
    }
    response = requests.post(request_url, json=request_body)
    assert response.status_code == 404
    response_boilerplate_checks(response)
