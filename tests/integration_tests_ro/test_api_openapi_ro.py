"""API Read-Only Integration Tests (OpenAPI)

Read-only tests to validate the OpenAPI documentation was generated correctly.

We do not need to validate against the OpenAPI spec.  We have other tests in
the pipeline for that.  Use these tests to check for Videon-specific info.

OpenAPI file should be in YAML so parse it with PyYAML.
https://pyyaml.org/wiki/PyYAMLDocumentation

"""
import json
import yaml
import os
import urllib.request

from urllib.parse import urljoin

api_gateway_url = os.environ["API_GATEWAY_URL"]
api_version_str = os.environ["API_VERSION_STR"]

###############################################################################
# Fetch the OpenAPI documents from their public URLs
###############################################################################
test_url = urljoin(api_gateway_url, "openapi/json")
with urllib.request.urlopen(test_url) as response:
    openapi_json_str = response.read().decode("utf-8")
openapi_json_obj = json.loads(openapi_json_str)

test_url = urljoin(api_gateway_url, "openapi/json")
with urllib.request.urlopen(test_url) as response:
    openapi_yaml_str = response.read().decode("utf-8")
openapi_yaml_obj = yaml.safe_load(openapi_yaml_str)

# The master copy of our OpenAPI documentation contains a lot of extra info
# for AWS to generate the API Gateway, as well as several internal API paths
# that we use for internal testing.  We scrub this from the documents.
# Make sure it worked, and nothing slipped through!
internal_only_strings = [
    "x-amazon", "{proxy+}", "test-auth", "VIDEON_INTERNAL_AUTH"
]

###############################################################################
# Make sure the JSON version has the expected data
###############################################################################


def test_json_info_version():
    assert openapi_json_obj["info"].get("version") == api_version_str


def test_json_servers():
    assert len(openapi_json_obj["servers"]) == 1


def test_json_servers_url():
    assert openapi_json_obj["servers"][0].get("url") == api_gateway_url


def test_json_internal_only_strings():
    for internal_string in internal_only_strings:
        assert internal_string not in openapi_json_str


###############################################################################
# Make sure the YAML version has the expected data
###############################################################################


def test_yaml_info_version():
    assert openapi_yaml_obj["info"].get("version") == api_version_str


def test_yaml_servers():
    assert len(openapi_yaml_obj["servers"]) == 1


def test_yaml_servers_url():
    assert openapi_yaml_obj["servers"][0].get("url") == api_gateway_url


def test_yaml_internal_only_strings():
    for internal_string in internal_only_strings:
        assert internal_string not in openapi_yaml_str
