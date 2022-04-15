"""Request Handler for /openapi/xxxxx API Routes

This is implemented as a Lambda Proxy integration.  The function is
responsible for validating the input, and sending a properly-formatted
response.  (Failure to do so will be a 5xx error for the client.)

https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
https://docs.aws.amazon.com/apigateway/latest/developerguide/handle-errors-in-lambda-integration.html
"""

import boto3
import logging
import videon_shared as videon

from os import environ

_s3_bucket_name = environ.get("S3_BUCKET_NAME")
_openapi_html_document = environ.get("OPENAPI_HTML_DOCUMENT")
_openapi_json_document = environ.get("OPENAPI_JSON_DOCUMENT")
_openapi_yaml_document = environ.get("OPENAPI_YAML_DOCUMENT")
_api_gateway_url = environ.get("API_GATEWAY_URL")

s3 = boto3.resource("s3")

logger = logging.getLogger()


def lambda_handler(event, context):  # pylint: disable=unused-argument

    videon.setup_logging(logging.INFO, event)

    base = "/openapi"

    # If these fail the API gateway is misconfigured
    supported_methods = ("GET", "OPTIONS")
    assert event["httpMethod"] in supported_methods
    assert event["resource"] in {
        base, f"{base}/", f"{base}/json", f"{base}/yaml", f"{base}/html"
    }

    # CORS Preflight
    if event["httpMethod"] == "OPTIONS":
        return videon.response_cors(", ".join(supported_methods))

    # We cannot use our standard response_json() function here because we
    # return raw file content.
    if event["resource"] == f"{base}/json":
        logger.info("Request for JSON OpenAPI document...")
        return {
            "isBase64Encoded": False,
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            },
            "body": f"{get_text_file(_openapi_json_document)}"
        }
    elif event["resource"] == f"{base}/yaml":
        logger.info("Request for YAML OpenAPI document...")
        return {
            "isBase64Encoded": False,
            "statusCode": 200,
            "headers": {
                # YAML does not have a well agreed upon MIME type.
                # https://stackoverflow.com/questions/332129/yaml-media-type
                "Content-Type": "text/vnd.yaml",
                "Access-Control-Allow-Origin": "*"
            },
            "body": f"{get_text_file(_openapi_yaml_document)}"
        }
    elif event["resource"] == f"{base}/html":
        logger.info("Request for HTML OpenAPI document...")
        return {
            "isBase64Encoded": False,
            "statusCode": 200,
            "headers": {
                "Content-Type": "text/html",
                "Access-Control-Allow-Origin": "*"
            },
            "body": f"{get_text_file(_openapi_html_document)}"
        }
    else:
        logger.info("Non-specific OpenAPI request, redirect to HTML version...")
        return {
            "isBase64Encoded": False,
            "statusCode": 301,
            "headers": {
                "Location": f"{_api_gateway_url}openapi/html",
                "Content-Type": "text/plain",
                "Access-Control-Allow-Origin": "*"
            },
            "body": f"Visit {_api_gateway_url}openapi/html"
        }


def get_text_file(object_name):
    """Get the OpenAPI document from S3 and return the contents as a string.

    All the S3 logic should be here so we do not have to duplicate code for
    each path (YAML vs JSON vs HTML).
    """
    object = s3.Object(_s3_bucket_name, object_name).get()
    # Body is a StreamingBody.
    # Read everything in one shot, but if our OpenAPI definition becomes
    # massive in the future, we may need to break this up.
    # https://botocore.amazonaws.com/v1/documentation/api/latest/reference/response.html
    file_contents = object["Body"].read().decode("utf-8")
    # Close the HTTP connection to be a good citizen.
    object["Body"].close()

    # Populate the URL of the API Gateway
    # In the redoc-cli static HTML, the URL is represented in a funny way,
    # so fix that.
    file_contents = file_contents.replace("/$URL", _api_gateway_url[:-1])
    file_contents = file_contents.replace("$URL", _api_gateway_url)

    return file_contents
