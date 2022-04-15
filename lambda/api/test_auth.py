"""Handler for an authentication test API route (/test-auth)

You can perform requests against this route to verify the Lambda authorizer
worked.  Useful for validating authentication changes without needing to pass
in a bunch of parameters.
"""
import videon_shared as videon

# Enable X-Ray Tracing
from aws_xray_sdk.core import patch_all

patch_all()


def lambda_handler(event, context):  # pylint: disable=unused-argument

    # If this fails the API gateway is misconfigured
    supported_methods = ("GET", "OPTIONS")
    assert event["httpMethod"] in supported_methods

    if event["httpMethod"] == "GET":
        return videon.response_json(
            200, {"message": "Authentication was successful."}, event)
    else:  # OPTIONS - CORS preflight
        return videon.response_cors(", ".join(supported_methods))
