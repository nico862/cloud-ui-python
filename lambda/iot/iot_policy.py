"""Handler for updating IOT policies.

Versioning is not yet available via the CDK so when creating the stack,
we create a CustomResource and this handler handles versioning.
"""

import logging
from typing import Any

import boto3

iot = boto3.client("iot")

logger = logging.getLogger()


def on_event(event, context):  # pylint: disable=unused-argument
    logger.info(event)
    request_type = event["RequestType"].lower()
    if request_type == "create":
        return on_create(event)
    if request_type == "update":
        return on_update(event)
    if request_type == "delete":
        return on_delete(event)
    raise Exception(f"Invalid request type: {request_type}")


def on_create(event):
    props = event["ResourceProperties"]
    logger.info("Create new resource with props=%s", props)

    create_policy(policy_name=props["policy_name"],
                  policy_document=props["policy_document"])
    physical_id = physical_id_from_policy_name(props["policy_name"])
    return {"PhysicalResourceId": physical_id}


def on_update(event):
    physical_id = event["PhysicalResourceId"]
    props = event["ResourceProperties"]
    old_props = event["OldResourceProperties"]
    logger.info("Update resource %s with props=%s, old_props=%s", physical_id,
                props, old_props)

    policy_name = props["policy_name"]
    old_policy_name = old_props["policy_name"]
    if policy_name != old_policy_name:
        physical_id = physical_id_from_policy_name(policy_name)
        create_policy(policy_name=props["policy_name"],
                      policy_document=props["policy_document"])

    try:
        response = iot.list_policy_versions(policyName=policy_name)
    except iot.exceptions.ResourceNotFoundException:
        return on_create(event)

    policy_versions = response.get("policyVersions", [])
    if len(policy_versions) >= 5:
        delete_oldest_version(policy_name=policy_name,
                              policy_versions=policy_versions)

    policy_document = props["policy_document"]
    response = iot.create_policy_version(policyName=policy_name,
                                         policyDocument=policy_document,
                                         setAsDefault=True)

    logger.info(
        "Updated iot policy, physical_id=%s, response=%s, policy_document=%s",
        physical_id, response, policy_document)

    return {"PhysicalResourceId": physical_id}


def on_delete(event):
    physical_id = event["PhysicalResourceId"]
    props = event["ResourceProperties"]

    policy_name = props["policy_name"]

    try:
        response = iot.list_policy_versions(policyName=policy_name)
    except iot.exceptions.ResourceNotFoundException:
        logger.warning("Unable to find policy %s to delete", policy_name)
        return {"message": "Unable to delete policy"}
    for version in response.get("policyVersions"):
        if not version["isDefaultVersion"]:
            version_id = version["versionId"]
            logger.info("Deleting policy version: %s.%s", policy_name,
                        version_id)
            response = iot.delete_policy_version(policyName=policy_name,
                                                 policyVersionId=version_id)
            logger.debug("response=%s", response)
    logger.info("Deleting policy %s", policy_name)
    response = iot.delete_policy(policyName=policy_name)
    logger.debug("response=%s".response)
    return {"PhysicalResourceId": physical_id}


def delete_oldest_version(policy_name, policy_versions):
    non_default_versions = [
        ver for ver in policy_versions if not ver["isDefaultVersion"]
    ]
    oldest_version = min(non_default_versions,
                         default=None,
                         key=lambda version: version["versionId"])
    if oldest_version:
        iot.delete_policy_version(policyName=policy_name,
                                  policyVersionId=oldest_version["versionId"])
        logger.info("Deleted policy version policy_name=%s, versionId=%s",
                    policy_name, oldest_version["versionId"])


def physical_id_from_policy_name(policy_name: str) -> str:
    return f"CustomIotPolicy{policy_name}"


def create_policy(policy_name: str, policy_document: Any):
    response = iot.create_policy(policyName=policy_name,
                                 policyDocument=policy_document)
    logger.info("Created policy response=%s", response)
