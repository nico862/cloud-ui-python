"""Handler for an authentication info API route (/auth-info)

This route is unauthenticated.  It is used by the frontend to determine
how the user should sign in (Cognito User Pool, Facebook, corporate SAML,
etc.).  Basic flow:

 1. At the login screen, the user enters their email address (no PW prompt).
 2. The frontend calls this API and passed the user's email.
 3. The API responds with the necessary info for the frontend to call
    the Cognito AUTHORIZATION Endpoint and start the sign in flow.
    https://docs.aws.amazon.com/cognito/latest/developerguide/authorization-endpoint.html
 4. The frontend calls Cognito using the provided API parameters, which will
    lead to one of the following:
      a. Cognito auth challenge (no SSO, no social sign in)
          - Password prompt page rendered in our frontend
          - May be followed by MFA prompt
      b. Redirect to Facebook
      c. Redirect to Google
      d. Redirect to Amazon
      e. Redirect to Apple
      f. Redirect to corporate Identity Provider (SAML/OIDC)

Note this API should not leak any sensitive info.
 - Do not disclose whether or not a user exists.  The auth info for a
   non-existent user will be returned as identity_provider=COGNITO, or
   possibly idp_identifier=userdomain.com if the user's email domain matches
   a registered SAML/OIDC IDP.
 - Do not leak the identity provider name if the user's email domain matches
   a registered SAML/OIDC IDP (which may disclose customer info).  Instead of
   returning identity_provider, return idp_identifier, which should equal the
   user's email domain.

"""
import boto3
import logging
import re
import videon_shared as videon

from os import environ

# Enable X-Ray Tracing
from aws_xray_sdk.core import patch_all

patch_all()

COGNITO_REGION = environ.get("COGNITO_REGION")
COGNITO_USER_POOL_CLIENT_ID = environ.get("COGNITO_USER_POOL_CLIENT_ID")
COGNITO_USER_POOL_DOMAIN = environ.get("COGNITO_USER_POOL_DOMAIN")
COGNITO_USER_POOL_ID = environ.get("COGNITO_USER_POOL_ID")

cognito = boto3.client("cognito-idp")

logger = logging.getLogger()


def lambda_handler(event, context):  # pylint: disable=unused-argument

    videon.setup_logging(logging.INFO, event)

    # If this fails the API gateway is misconfigured
    supported_methods = ("GET", "OPTIONS")
    assert event["httpMethod"] in supported_methods

    if event["httpMethod"] == "GET":
        email = event["queryStringParameters"].get("email")
        logger.info("User email %s", email)

        # The API gateway will validate that the required parameter was
        # passed in, but not that it is in the proper email format.
        # Check that here.
        if not re.match(
                r"^[a-zA-Z0-9_+&*-]+(?:\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,7}$",
                email):
            return videon.response_json(
                400, {"message": "Email not in proper format."}, event)

        return videon.response_json(200, get_auth_info(email), event)
    else:  # OPTIONS - CORS preflight
        return videon.response_cors(", ".join(supported_methods))


def get_auth_info(email):
    """Returns the authentication info for the specified user.
    Should return a dict with all the info necessary to initiate a Cognito
    Auth Flow.
    """

    email_domain = (email.split("@"))[1]
    logger.info("User email domain %s", email_domain)

    # See if the user's email domain has been registered for a corporate SSO
    # system with SAML/OIDC (e.g. All ibm.com users are federated through IBM's
    # corporate identity provider).
    #
    # Any identity providers setup in Cognito should have the identifier field
    # populated with a list of the email domains they handle.
    # https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-managing-saml-idp-naming.html
    try:
        response = cognito.get_identity_provider_by_identifier(
            UserPoolId=COGNITO_USER_POOL_ID, IdpIdentifier=email_domain)
    except cognito.exceptions.ResourceNotFoundException:
        logger.info(
            "Could not find an Identity Provider for %s, user not SAML/OIDC.",
            email_domain)
        response = None
    if response is not None:
        logger.info(
            "Matching Identity Provider found for %s, user is SAML/OIDC.",
            email_domain)
        idp_identifier = email_domain
        identity_provider = None
    else:
        # Not a SAML/OIDC SSO User
        idp_identifier = None
        # See if the user exists.  If so, grab the username attribute, which
        # will tell us if the user has their password stored in Cognito, or
        # they are using social sign on.  Usernames are generally in the
        # following formats:
        #   xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx = Cognito Internal
        #   facebook_xxxxxxxxxxxxxxxxx = Facebook
        #   google_xxxxxxxxxxxxxxxxx   = Google
        #   amazon_xxxxxxxxxxxxxxxxx   = Amazon
        #   apple_xxxxxxxxxxxxxxxxx    = Apple
        # Note that I could not find any "hard" rules about Cognito username
        # formats, so this may have to evolve over time.
        response = cognito.list_users(UserPoolId=COGNITO_USER_POOL_ID,
                                      Filter=f"email = \"{email}\"")
        # identity_provider should be in a format suitable for the Cognito
        # AUTHORIZATION endpoint.
        # https://docs.aws.amazon.com/cognito/latest/developerguide/authorization-endpoint.html
        if len(response["Users"]) > 0:
            logger.info("User email found in Cognito with Username %s.",
                        response["Users"][0]["Username"])
            if re.search("facebook", response["Users"][0]["Username"],
                         re.IGNORECASE):
                identity_provider = "Facebook"
            elif re.search("google", response["Users"][0]["Username"],
                           re.IGNORECASE):
                identity_provider = "Google"
            elif re.search("amazon", response["Users"][0]["Username"],
                           re.IGNORECASE):
                identity_provider = "LoginWithAmazon"
            elif re.search("apple", response["Users"][0]["Username"],
                           re.IGNORECASE):
                identity_provider = "SignInWithApple"
            else:
                identity_provider = "COGNITO"
        else:
            # If the user is not found, Users will be an empty list.
            # Return Cognito in that case, so we do not disclose the existence
            # (or lack thereof) of the user.
            identity_provider = "COGNITO"

    # For Cognito and social users, identity_provider should be set.
    # For SAML/OIDC SSO users, idp_identifier should be set.
    # But not both.
    assert (identity_provider is None) or (idp_identifier is None)

    # Return all the necessary info for the frontend to call the
    # Authorization Endpoint
    return {
        "cognito_region": COGNITO_REGION,
        "cognito_user_pool_id": COGNITO_USER_POOL_ID,
        "client_id": COGNITO_USER_POOL_CLIENT_ID,
        "oauth2_url": f"https://{COGNITO_USER_POOL_DOMAIN}/oauth2",
        "idp_identifier": idp_identifier,
        "identity_provider": identity_provider
    }
