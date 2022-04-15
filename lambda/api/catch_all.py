"""Catch-All Handler for API Gateway

This Lambda handles any API routes and methods that are not explicitly covered
in our API gateway definition.  We will use this to return a helpful 404.
"""
import videon_shared as videon

# Enable X-Ray Tracing
from aws_xray_sdk.core import patch_all

patch_all()


def lambda_handler(event, context):  # pylint: disable=unused-argument
    return videon.response_json(404, {"message": "Not a valid API route"},
                                event)
