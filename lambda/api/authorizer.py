"""Authenticates and authorizes requests to the API Gateway.

Gets invoked for (almost) every request. It is responsible for handling all
of the authentication methods we support.

This is the definitive guide on writing a custom authorizer function:
https://www.alexdebrie.com/posts/lambda-custom-authorizers/

Try to optimize for performance in this function, since it gets called a lot.
Return as quickly as possible.  You can enable caching in the API Gateway
config based on the HTTP Authorization header, but note that the IAM policy
you return will have to be broad enough to cover all API
methods/routes/endpoint that particular user may access.  And even with
caching, you should still be sensitive to performance.  This can bottleneck
our entire API!

This script requires some external packages for parsing JWT tokens and making
REST API calls.  Since the vanilla AWS runtime has a limited set of libraries,
we bundle our third party packages into the videon_shared Lambda layer (along
with our own shared functions), which is automatically extracted under /opt in
the include path.  See README.md for more info about managing external
dependencies.
"""

import boto3
import json
import logging
import requests
import sys
import time
import urllib.request
import videon_shared as videon

from jose import jwk, jwt
from jose.utils import base64url_decode
from os import environ
from requests.structures import CaseInsensitiveDict

# Enable X-Ray Tracing
from aws_xray_sdk.core import patch_all

patch_all()

# Code that runs in the global context (not inside a function) MAY have its
# state preserved between function invocations.
# Use this for data that we want to cache, but be aware it may be stale.
# https://aws.amazon.com/blogs/compute/container-reuse-in-lambda/

_cognito = boto3.client("cognito-idp")
# The structure for this URL is published here:
# https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html
_cognito_keys_url = \
    f"{environ.get('COGNITO_USER_POOL_URL')}/.well-known/jwks.json"
_cognito_client_id = environ.get("COGNITO_USER_POOL_CLIENT_ID")
_cognito_user_pool_id = environ.get("COGNITO_USER_POOL_ID")
_cognito_global_admins_group_name = environ.get(
    "COGNITO_GLOBAL_ADMINS_GROUP_NAME")
_cognito_global_users_group_name = environ.get(
    "COGNITO_GLOBAL_USERS_GROUP_NAME")
_cognito_global_readers_group_name = environ.get(
    "COGNITO_GLOBAL_READERS_GROUP_NAME")
_cognito_device_management_group_name = environ.get(
    "COGNITO_DEVICE_MANAGEMENT_GROUP_NAME")
_cognito_user_management_group_name = environ.get(
    "COGNITO_USER_MANAGEMENT_GROUP_NAME")
_cognito_organization_management_group_name = environ.get(
    "COGNITO_ORGANIZATION_MANAGEMENT_GROUP_NAME")
_videon_internal_auth_arn = environ.get("VIDEON_INTERNAL_AUTH_ARN")

_restapi_url_path = environ.get("RESTAPI_URL_PATH")

# Download Cognito public keys.
# Instead of re-downloading the public keys every invocation,
# we download them only on cold start.
with urllib.request.urlopen(_cognito_keys_url) as f:
    print(f"-- Downloading Cognito public keys from {_cognito_keys_url}...")
    _cognito_response = f.read()
_cognito_keys = json.loads(_cognito_response.decode("utf-8"))["keys"]

# Get the VIDEON_INTERNAL_AUTH token from Secrets Manager.
# Because Secrets Manager has a rate limit, we will only query it on cold start.
# Because Lambda containers may linger for a while, it is possible we will
# have an old version of the secret in memory.  To mitigate this, we will get
# all available versions of the secret (current, pending, and previous).
_secretsmanager = boto3.client("secretsmanager")
# Not all of these secret versions may exist, depending on the rotation status.
# Only check the ones we can find.
_videon_internal_auth_secret = _secretsmanager.describe_secret(
    SecretId=_videon_internal_auth_arn)
if "AWSCURRENT" in str(_videon_internal_auth_secret):
    _videon_internal_auth_current = _secretsmanager.get_secret_value(
        SecretId=_videon_internal_auth_arn, VersionStage="AWSCURRENT")
else:
    _videon_internal_auth_current = None
if "AWSPENDING" in str(_videon_internal_auth_secret):
    _videon_internal_auth_pending = _secretsmanager.get_secret_value(
        SecretId=_videon_internal_auth_arn, VersionStage="AWSPENDING")
else:
    _videon_internal_auth_pending = None
if "AWSPREVIOUS" in str(_videon_internal_auth_secret):
    _videon_internal_auth_previous = _secretsmanager.get_secret_value(
        SecretId=_videon_internal_auth_arn, VersionStage="AWSPREVIOUS")
else:
    _videon_internal_auth_previous = None

_videon_internal_headers = {
    "Authorization":
        "VIDEON_INTERNAL_AUTH " + _videon_internal_auth_current["SecretString"]
}

logger = logging.getLogger()


def lambda_handler(event, context):  # pylint: disable=unused-argument
    """Lambda function entry point (start here).

    Process the input data in the event object.
    https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-input.html
   """
    videon.setup_logging(logging.INFO, event)

    method_arn = event["methodArn"]
    user_guid = None

    # HTTP headers are case-insensitive, but Python is case-sensitive.
    # This makes it painful to look up headers by name.
    # The requests package has a case-insensitive dict for this purpose.
    headers = CaseInsensitiveDict(event["headers"])
    authorization = headers["Authorization"]
    source_ip = headers["X-Forwarded-For"]

    # Authorization header must be set before this function would be called,
    # so this is really just a sanity check.
    if authorization is None:
        logger.info("Authorization header is missing, request not authorized!")
        return generate_policy("AUTHORIZATION_HEADER_MISSING", "Deny", "*")

    # Check the Authorization header.  It is required in the API Gateway
    # Authorizer config, so we know that if this function is being called,
    # it is populated. There are three scenarios we need to cover:
    #
    #    1. An internal call from within the platform (Authorization =
    #       "VIDEON_INTERNAL_AUTH uzqJnPmXNRbaYbHVnE2z6wykDqBKD1hE").
    #       Verify the token against the Secrets Manager and return Allow.
    #
    #    2. Personal Access Token (Authorization =
    #       "PAT ABCDEFXkKsTwCfWs6B1JIxXra9GQY8B6").
    #       Verify the token, obtain the user GUID, and continue.
    #
    #    3. Cognito-authorized User (Authorization =
    #       "Bearer COGNITO_JWT_ACCESS_TOKEN").  Verify the token against our
    #       Cognito User Pool, obtain the user GUID, and continue.
    #       Note we use the Access Token, NOT the Identity or Refresh tokens.
    #
    # Authorization header should be in the format: "AUTH_TYPE CREDENTIALS"
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
    # There are a few standard auth types:
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication
    # We can also make up our own (Amazon does it).  Try to use a standard
    # one where appropriate (e.g. Cognito is an Oauth Bearer token in JWT
    # format).

    if authorization.startswith("VIDEON_INTERNAL_AUTH "):
        # Internal requests from within the application (perhaps even from
        # this function!).
        logger.info(
            "Authorization header from %s starts with "
            "\"VIDEON_INTERNAL_AUTH\", assuming internal call...", source_ip)
        # Remove auth method + space prefix so we only have to deal with the
        # token value.
        return verify_internal_token(authorization[21:], method_arn)
    elif authorization.startswith("PAT "):
        logger.info(
            "Authorization header from %s starts with "
            "\"PAT\", assuming Personal Access Token...", source_ip)
        # Remove auth method + space prefix so we only have to deal with the
        # token value.
        user_guid = verify_pat_token(authorization[4:])
    elif authorization.startswith("Bearer "):
        logger.info(
            "Authorization header from %s starts with "
            "\"Bearer\", assuming Cognito...", source_ip)
        # Remove auth method + space prefix so we only have to deal with the
        # token value.
        user_guid = verify_cognito_token(authorization[7:])
    else:
        logger.error(
            "Authorization header from %s starts with \"%s\","
            "unrecognized format, denied!", source_ip, authorization[15:])
        return generate_policy("UNRECOGNIZED_AUTH_HEADER", "Deny", "*")

    # If user_guid is set, we were able to verify the auth header and trace it
    # back to a user.  Now we need to check the permissions that user should
    # have.
    if user_guid is None:
        logger.error("Unable to match request to a valid user, denied!")
        return generate_policy("UNABLE_TO_MATCH_USER", "Deny", "*")

    logger.info("User %s verified, checking access levels...", user_guid)

    # Debug test of internal auth, delete later.
    # internal_request_headers = requests.structures.CaseInsensitiveDict()
    # internal_request_headers["Accept"] = "application/json"
    # internal_request_headers[
    #     "Authorization"] = \
    # f"VIDEON_INTERNAL_AUTH {_videon_internal_auth_current["SecretString"]}"
    # resp = requests.get(
    #     "https://7se3mnbq31.execute-api.us-west-2.amazonaws.com/v1/test-auth",
    #     headers=internal_request_headers)
    # logger.info(resp.status_code)
    # logger.info(resp.headers)

    # TODO LOOK UP USER_GUID MEMBERSHIP AND ACCESS LEVEL IN ORGANIZATIONS
    # AND ADD TO POLICY CONTEXT

    # TODO LOOK UP USER_GUID MEMBERSHIP AND ACCESS LEVEL IN FLEETS
    # AND ADD TO POLICY CONTEXT

    # TODO SEE IF USER_GUID IS A MEMBER OF ANY GLOBAL GROUPS IN COGNITO
    # AND ADD TO POLICY CONTEXT
    try:
        user_groups = list_cognito_groups(user_guid)
    # This should only be needed for the placeholder PATs
    # (myrontest and skeleton key)
    except _cognito.exceptions.UserNotFoundException:
        user_groups = None

    # Note we may need to adjust the resource statement here to be more
    # cache-friendly:
    # https://www.alexdebrie.com/posts/lambda-custom-authorizers/#caching-your-custom-authorizers
    return generate_policy(user_guid, "Allow", event["methodArn"], user_groups)


def generate_policy(principal_id, effect, method_arn, user_groups=None):
    """Generates IAM Policy to be the return data from this Lambda function.

    https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-output.html

    https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-control-access-using-iam-policies-to-invoke-api.html#api-gateway-calling-api-permissions
    """
    auth_response = {}
    auth_response["principalId"] = principal_id

    if effect and method_arn:
        policy_document = {
            "Version":
                "2012-10-17",
            "Statement": [{
                "Action": "execute-api:Invoke",
                "Effect": effect,
                "Resource": method_arn
            }]
        }

        auth_response["policyDocument"] = policy_document

    if user_groups is None:
        user_groups = []
    # AWS does not allow json objects or arrays as part of
    # the context, so stringify the list of groups
    user_groups_stringified = json.dumps(user_groups)
    auth_response["context"] = {
        "UserGUID": principal_id,
        "UserGroups": user_groups_stringified
    }

    return auth_response


def is_user_ok(user_guid):
    """Check the status of the user account in Cognito.

    See if they are disabled or have another problem with their account that
    should prevent access to the API.

    Returns True if the User is OK to to access the API, False otherwise.
    """
    response = _cognito.admin_get_user(Username=user_guid,
                                       UserPoolId=_cognito_user_pool_id)
    # https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UserType.html
    if response["Enabled"] is False:
        return False

    # These are the only user statuses we consider "OK".
    # We allow unconfirmed email users into the system so they can get going.
    if response["UserStatus"] == "CONFIRMED":
        return True
    if response["UserStatus"] == "UNCONFIRMED":
        return True

    # Any other user status is "bad".
    return False


def list_cognito_groups(user_guid):
    """Check to see if user is a member of any Cognito groups

    We will use these groups to grant "global" permissions to users that
    are not tied to a specific Organization/Fleet (e.g. Videon customer
    support employees).

    Returns list of the groups the user is a member of (may be empty list).
    """
    # This is mostly academic because I doubt we will ever be a member of
    # enough groups to trigger pagination.  However, I do not want to be bit
    # by this as a bug later.
    response = _cognito.admin_list_groups_for_user(
        Username=user_guid, UserPoolId=_cognito_user_pool_id)
    groups = response["Groups"]
    while "NextToken" in response:
        response = _cognito.admin_list_groups_for_user(
            Username=user_guid,
            UserPoolId=_cognito_user_pool_id,
            NextToken=response["NextToken"])
        groups.extend(response["Groups"])
    return [group["GroupName"] for group in groups]


def verify_cognito_token(token):
    """Verifies the Cognito JWT token agains our User Pool.

    Based on code from here:
    https://github.com/awslabs/aws-support-tools/tree/master/Cognito/decode-verify-jwt

    Return User GUID (sub) if verified, otherwise None.
    """
    # get the kid from the headers prior to verification
    # jose may throw an exception here if the JWT is malformed.
    # Handle that scenario so we can properly return "access denied",
    # rather than terminating improperly, which gives the client an
    # ugly 500 error.
    try:
        headers = jwt.get_unverified_headers(token)
    except Exception as e:  # pylint: disable=broad-except
        log_message = (\
        "Could not parse JWT token, Cognito user not verified!"
        f"\nException Type = {type(e)}"
        f"\nException Args = {e.args}"
        f"\nException = {e}"
        f"\nexc_info = {sys.exc_info()[0]}")
        logger.warning(log_message)
        return None
    kid = headers["kid"]
    # search for the kid in the downloaded public keys
    key_index = -1
    for i in range(len(_cognito_keys)):
        if kid == _cognito_keys[i]["kid"]:
            key_index = i
            break
    if key_index == -1:
        # This will trigger a 500 error to the client, which is appropriate,
        # because we screwed up internally.
        raise Exception("Public key not found in jwks.json, "
                        "were we unable do download them from Cognito?")
    # construct the public key
    public_key = jwk.construct(_cognito_keys[key_index])
    # get the last two sections of the token,
    # message and signature (encoded in base64)
    message, encoded_signature = str(token).rsplit(".", 1)
    # decode the signature
    decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))
    # verify the signature
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        logger.warning("JWT Signature verification failed, "
                       "Cognito user not verified!")
        return None
    logger.info("JWT Signature successfully verified")
    # since we passed the verification, we can now safely
    # use the unverified claims
    claims = jwt.get_unverified_claims(token)
    # Check the token expiration
    if time.time() > claims["exp"]:
        logger.warning("JWT Token is expired, Cognito user not verified!")
        return None
    # Check the Audience (use claims["aud"] if verifying an identity token)
    if claims["client_id"] != _cognito_client_id:
        logger.warning(
            "JWT Token was not issued for this audience/client_id, "
            "expected %s, got %s. Cognito user not verified!",
            _cognito_client_id, claims["client_id"])
        return None
    # Check the token type to mane sure no one pulled a sneaky
    if claims["token_use"] != "access":
        logger.warning("JWT Token is not an access token, "
                       "Cognito user not verified!")
        return None
    # sub contains the user GUID
    return claims["sub"]


def verify_internal_token(token, method_arn):
    """Verifies the VIDEON_INTERNAL_AUTH token is valid.

    The internal auth token value is auto-generated, stored in the
    Secrets Manager, and rotated frequently.  Due to issues with re-used
    Lambda containers which may have old versions of the token cached,
    we will check the supplied token against the current, previous, and
    pending versions of the secret.

    Returns an IAM policy with the appropriate permissions so lambda_handler
    can return immediately (optimize for performance here).
    """

    # If one of these versions is not set, it will have a value of None.
    if _videon_internal_auth_current is not None and token == \
    _videon_internal_auth_current["SecretString"]:
        logger.info("Internal auth token matches AWSCURRENT "
                    "version of secret.")
    elif _videon_internal_auth_previous is not None and token == \
    _videon_internal_auth_previous["SecretString"]:
        logger.info("Internal auth token matches AWSPREVIOUS "
                    "version of secret.")
    elif _videon_internal_auth_pending is not None and token == \
    _videon_internal_auth_pending["SecretString"]:
        logger.info("Internal auth token matches AWSPENDING "
                    "version of secret.")
    else:
        logger.error("Internal auth token does not match Secrets Manager, "
                     "verify failed!")
        return generate_policy("VIDEON_INTERNAL_AUTH_INVALID", "Deny", "*")

    # If we made it here, the token is valid.
    # Internal callers should have read access to everything,
    # the ability to generate audit log events, and restricted
    # write access.
    # We do not have to do any additional lookup on the requestor.
    # We know his permissions, so return an IAM policy so we can exit quickly.
    # Use the method ARN to construct an IAM policy with the right resources
    # in it. method ARN should look like this:
    # arn:aws:execute-api:us-west-2:458280733286:vh6w5bkk12/v1/GET/devices
    resource_base = method_arn.split("/")[0]
    auth_response = {}
    auth_response["principalId"] = "VIDEON_INTERNAL_AUTH"
    auth_response["policyDocument"] = {
        "Version":
            "2012-10-17",
        "Statement": [{
            "Action":
                "execute-api:Invoke",
            "Effect":
                "Allow",
            "Resource": [
                f"{resource_base}/*/GET/*",
                f"{resource_base}/*/POST/audit",
                f"{resource_base}/*/PUT/audit",
                f"{resource_base}/*/PATCH/audit",
                f"{resource_base}/*/DELETE/audit",
                f"{resource_base}/*/POST/orgs/*/users",
                f"{resource_base}/*/POST/users",
                f"{resource_base}/*/PATCH/pats",
            ]
        }]
    }

    return auth_response


def verify_pat_token(token):
    """Verifies the provided token is valid.

    Return User GUID (sub) if verified, otherwise None.
    """
    # TODO: remove. For testing purposes.
    if token == "myrontest":
        logger.info("Placeholder PAT %s authorized!", token)
        return "54c25fb2-a2b9-4ccc-85b7-e1c5075fcda1"

    token_hash = videon.get_sha256_hash(token)
    logger.info("Verify personal access token with hash %s", token_hash)

    verify_token_url = f"{_restapi_url_path}pats"
    verify_token_request_body = {"token_hash": token_hash}
    verify_token_response = requests.patch(
        verify_token_url,
        data=json.dumps(verify_token_request_body),
        headers=_videon_internal_headers)
    verify_token_response_body = verify_token_response.json()

    if verify_token_response.status_code != 200:
        logger.warning(
            "Received status code %s while verifying token. "
            "Response body: %s", verify_token_response.status_code,
            verify_token_response_body)
    else:
        logger.info("Personal access token successfully verified")

    return verify_token_response_body.get("user_guid")
