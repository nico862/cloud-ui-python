"""Rotates Secrets Manager Entry for VIDEON_INTERNAL_AUTH token.

This Lambda function is called by Secrets Manager at regular intervals to
rotate the secret.  Rotating a secret is a multi-step process, and there is
a defined format for the event[] input.
https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets-lambda-function-overview.html

AWS provides some examples we can follow:
https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_available-rotation-templates.html

Based on the following reference code:
https://github.com/aws-samples/aws-secrets-manager-rotation-lambdas/blob/master/SecretsManagerRotationTemplate/lambda_function.py

This script requires some external packages for making REST API calls.  Since
the vanilla AWS runtime has a limited set of libraries, we bundle our third
party packages into the videon_shared Lambda layer (along with our own shared
functions), which is automatically extracted under /opt in the include path.
See README.md for more info about managing external dependencies.
"""

import boto3
import logging
import os
import requests

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):  # pylint: disable=unused-argument
    """Secrets Manager Rotation Template

    This is a template for creating an AWS Secrets Manager rotation lambda

    Args:
        event (dict): Lambda dictionary of event parameters. These keys must
            include the following:
            - SecretId: The secret ARN or identifier
            - ClientRequestToken: The ClientRequestToken of the secret
                                  version
            - Step: The rotation step (one of createSecret, setSecret,
                    testSecret, or finishSecret)

        context (LambdaContext): The Lambda runtime information

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and
                                   stage does not exist

        ValueError: If the secret is not properly configured for rotation

        KeyError: If the event parameters do not contain the expected keys

    """
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]

    # Setup the client
    service_client = boto3.client("secretsmanager")

    # Make sure the version is staged correctly
    metadata = service_client.describe_secret(SecretId=arn)
    if not metadata["RotationEnabled"]:
        logger.error("Secret %s is not enabled for rotation", arn)
        raise ValueError("Secret %s is not enabled for rotation" % arn)
    versions = metadata["VersionIdsToStages"]
    if token not in versions:
        logger.error(
            "Secret version %s has no stage for rotation of secret %s.", token,
            arn)
        raise ValueError(
            "Secret version %s has no stage for rotation of secret %s." % token,
            arn)
    if "AWSCURRENT" in versions[token]:
        logger.info(
            "Secret version %s already set as AWSCURRENT for secret %s.", token,
            arn)
        return
    elif "AWSPENDING" not in versions[token]:
        logger.error(
            "Secret version %s not set as AWSPENDING for rotation of "
            "secret %s.", token, arn)
        raise ValueError(
            "Secret version %s not set as AWSPENDING for rotation of secret %s."
            % (token, arn))

    if step == "createSecret":
        create_secret(service_client, arn, token)

    elif step == "setSecret":
        set_secret()

    elif step == "testSecret":
        test_secret(service_client, arn)

    elif step == "finishSecret":
        finish_secret(service_client, arn, token)

    else:
        raise ValueError("Invalid step parameter")


def create_secret(service_client, arn, token):
    """Create the secret

    This method first checks for the existence of a secret for the passed in
    token. If one does not exist, it will generate a new secret and put it
    with the passed in token.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the
                        secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and
                                   stage does not exist

    """
    # Make sure the current secret exists
    service_client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")

    # Now try to get the secret version, if that fails, put a new secret
    try:
        service_client.get_secret_value(SecretId=arn,
                                        VersionId=token,
                                        VersionStage="AWSPENDING")
        logger.info("createSecret: Successfully retrieved secret for %s.", arn)
    except service_client.exceptions.ResourceNotFoundException:
        # Generate a random password
        passwd = service_client.get_random_password(PasswordLength=32,
                                                    ExcludePunctuation=True)

        # Put the secret
        service_client.put_secret_value(SecretId=arn,
                                        ClientRequestToken=token,
                                        SecretString=passwd["RandomPassword"],
                                        VersionStages=["AWSPENDING"])
        logger.info(
            "createSecret: Successfully put secret for ARN %s and version %s.",
            arn, token)


def set_secret():
    """Set the secret

    This method should set the AWSPENDING secret in the service that the
    secret belongs to. For example, if the secret is a database credential,
    this method should take the value of the AWSPENDING secret and set the
    user"s password to this value in the database.

    """
    # This is where the secret should be set in the service
    logger.info(
        "setSecret: Skipping because this is a serverless application that "
        "does not have anything to set.")


def test_secret(service_client, arn):
    """Test the secret

    This method should validate that the AWSPENDING secret works in the
    service that the secret belongs to. For example, if the secret is a
    database credential, this method should validate that the user can
    login with the password in AWSPENDING and that the user has all of the
    expected permissions against the database.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier
    """
    # This is where the secret should be tested against the service
    videon_internal_auth_pending = service_client.get_secret_value(
        SecretId=arn, VersionStage="AWSPENDING")

    # Access the "test secret" URL using the AWSPENDING version of the secret.
    # This should be an authenticated API route we have prepared for this
    # purpose (testing the secret).  Our authorizer should be configured to
    # accept AWSPENDING, AWSCURRENT, and AWSPREVIOUS.
    request_headers = requests.structures.CaseInsensitiveDict()
    request_headers["Accept"] = "application/json"
    request_headers["Authorization"] = \
        f"VIDEON_INTERNAL_AUTH {videon_internal_auth_pending['SecretString']}"
    request_url = os.environ["TEST_SECRET_URL"]
    logger.info(
        "testSecret: Connecting to %s with AWSPENDING version of "
        "secret ARN %s...", request_url, arn)
    response = requests.get(request_url, headers=request_headers)
    logger.info("testSecret: %s responded with %s", request_url, str(response))
    if response.status_code == 200:
        logger.info("testSecret: %s responded OK, test passed.", request_url)
    else:
        raise Exception("testSecret: %s DID NOT RESPOND OK, TEST FAILED!" %
                        request_url)


def finish_secret(service_client, arn, token):
    """Finish the secret

    This method finalizes the rotation process by marking the secret version
    passed in as the AWSCURRENT secret.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the
                        secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn
                                   does not exist
    """
    # First describe the secret to get the current version
    metadata = service_client.describe_secret(SecretId=arn)
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                logger.info(
                    "finishSecret: Version %s already marked as "
                    "AWSCURRENT for %s", version, arn)
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    service_client.update_secret_version_stage(
        SecretId=arn,
        VersionStage="AWSCURRENT",
        MoveToVersionId=token,
        RemoveFromVersionId=current_version)
    logger.info(
        "finishSecret: Successfully set AWSCURRENT stage to version %s "
        "for secret %s.", token, arn)
