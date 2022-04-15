"""CDK Stack - Videon Cloud Platform REST API (OpenAPI Documentation)

This stack provides the implementation for the /openapi portion of our REST
API, as well as any sub-paths (e.g. /openapi/json).

The API paths, methods, inputs and outputs should all be defined per the
OpenAPI specification under /openapi.  The OpenAPI definition files are
used to generate the API Gateway.  The api_xxxxx stacks implement the
resources required to serve the APIs.

This stack should be considered a pseudo-microservice, and be relatively
self-contained.  It implements its own Lambda function handler(s), and any
stateful resources like DynamoDB tables or S3 buckets.  If it needs access any
of our other APIs, it should make a REST API call over HTTPS, using the
VIDEON_INTERNAL_AUTH token for authentication.
"""

import copy
import json
import re
import os
import yaml

from aws_cdk import (
    aws_lambda,  # lambda is a reserved word in Python, so use orig package name
    aws_s3_deployment as s3deploy,
    aws_s3 as s3,
    aws_iam as iam,
    aws_logs as cw_logs,
    core)

# Read the project version number from canonical source in version.py
# Available as __version__.
# Set a placeholder value to stop warnings about undefined variables.
__version__ = "See version.py"
__version_major__ = "See version.py"
exec(open("./version.py").read())  # pylint: disable=exec-used


class ApiOpenApiStack(core.Stack):
    """CDK Stack Class

    Requires the following parameters:
        apigw_restapi: SpecRestApi construct from the core API stack
        openapi_obj: OpenAPI document as a Python object.  We will sanitize
            the OpenAPI doc and strip out any internal info.
    """

    def __init__(self, scope: core.Construct, id: str, apigw_restapi,
                 apigw_url_export, openapi_obj, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Note: These files are referenced in bitbucket-pipelines.yml
        # so they are preserved between pipeline steps.  If you change them
        # here make sure to update the pipeline definition accordingly!
        openapi_html_document = "openapi.html"
        openapi_json_document = "openapi.json"
        openapi_yaml_document = "openapi.yml"

        # Sanitize OpenAPI Document
        # Remove any internal info that we used to generate the API Gateway
        # that should not be exposed to the public:
        #  - Any x-amazon-* extensions
        #  - Internal-only API paths:
        #       /              Root catch-all
        #       /{proxy+}      Catch-all
        #       /provisioning  Provisioning endpoints for device use only
        #       /test-auth     Test authentication for internal use only
        #  - Internal-only API methods:
        #       /pat PATCH  For internal token verification
        openapi_sanitized = filterobj(
            openapi_obj,
            r"(^(x\-amazon\-|\/test\-auth|\/provisioning|\/\{proxy\+\}))|^/$")
        pat_sanitized = filterobj(openapi_sanitized["paths"]["/pats"],
                                  r"(^patch)$")
        openapi_sanitized["paths"]["/pats"] = pat_sanitized

        # Filter out CORS requests
        for path in openapi_sanitized["paths"]:
            path_sanitized = filterobj(openapi_sanitized["paths"][path],
                                       r"(^options)$")
            openapi_sanitized["paths"][path] = path_sanitized

        # Overwrite the placeholder with the version number
        openapi_sanitized["info"]["version"] = __version__

        with open(openapi_json_document, "w") as outfile:
            json.dump(openapi_sanitized, outfile, indent=2)

        with open(openapi_yaml_document, "w") as outfile:
            yaml.dump(openapi_sanitized,
                      outfile,
                      default_flow_style=False,
                      width=80,
                      indent=2,
                      allow_unicode=False,
                      sort_keys=False)

        # Use the JSON version of the specification to generate human-friendly
        # browsable HTML documentation.  We will use a third-party CLI tool
        # called redoc-cli for this.
        #
        # Yes, I know os.system() is deprecated in favor of subprocess, however
        # redoc-cli seems to have problems parsing CLI parameters in the
        # Bitbucket pipeline.  Feel free to revisit in the future.
        #
        # There are ways redoc-cli can fail but still return a 0, so dump
        # stdout/stderr to a file so we can check.
        result = os.system(f"redoc-cli bundle {openapi_json_document} "
                           f"--output {openapi_html_document} "
                           f"> {openapi_html_document}-tmp 2>&1")

        with open(f"{openapi_html_document}-tmp", "rb") as tempfile:
            temptext = tempfile.read()

        if result != 0:
            print("-- Unable to generate OpenAPI HTML documentation!")
            print("-- Make sure redoc-cli is installed via npm, and you have")
            print("-- the same version listed in common_prerequisites.sh!")
            print(f"-- Program output: {temptext}")
            # This is probably a dealbreaker, so throw an exception.
            raise Exception

        if f"bundled successfully in: {openapi_html_document}".encode() \
        not in temptext:
            print("-- redoc-cli did not product the expected output!")
            print(f"-- Program output: {temptext}")
            raise Exception

        #######################################################################
        # BACK-END INFRASTRUCTURE
        # Declare any supporting resources for this API route, such as DynamoDB
        # tables and S3 buckets here.
        #######################################################################

        # We will store the OpenAPI documents in an S3 bucket, and the Lambda
        # handler will fetch them for requests.
        bucket = s3.Bucket(
            self,
            "S3Bucket",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            # Since this bucket contains auto-generated files only, let it
            # be destroyed on a teardown.
            removal_policy=core.RemovalPolicy.DESTROY,
            auto_delete_objects=True)

        # Copy the files to the S3 Bucket.
        s3deploy.BucketDeployment(
            self,
            "S3FileUpload",
            destination_bucket=bucket,
            sources=[
                s3deploy.Source.asset(
                    "./", exclude=["**", ".*", f"!{openapi_html_document}"]),
                s3deploy.Source.asset(
                    "./", exclude=["**", ".*", f"!{openapi_json_document}"]),
                s3deploy.Source.asset(
                    "./", exclude=["**", ".*", f"!{openapi_yaml_document}"])
            ],
            retain_on_delete=False)

        #######################################################################
        # LAMBDA LAYERS
        # Lambda layers are used to share code and Python packages between
        # functions/stacks.  To share code without creating complex inter-stack
        # dependencies, we will create the same layer in each stack, but
        # reference the same source directory.  Changes to the layer will
        # only be applied to stacks that are re-deployed.
        #######################################################################
        videon_shared_layer = aws_lambda.LayerVersion(
            self,
            "VideonSharedLayer",
            code=aws_lambda.Code.from_asset("lambda/videon_shared_layer"),
            compatible_runtimes=[aws_lambda.Runtime.PYTHON_3_9],
            description="Videon code shared between Lambda functions/stacks",
            layer_version_name=f"{id}-VideonSharedLayer-v{__version_major__}")

        #######################################################################
        # LAMBDA FUNCTIONS
        # These functions handle the API requests, and should be referenced
        # in the OpenAPI definition files.
        #######################################################################

        # This function handles requests for the JSON schema (/openapi/json).
        object_handler = aws_lambda.Function(
            self,
            "ObjectHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="object.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api_openapi"),
            description="Request Handler for /openapi API Routes",
            # Since this Lambda function is referenced in the OpenAPI
            # definition, we must have a fixed name.  Include version_major
            # in case we need to run multiple versions of the API
            # side-by-side.
            function_name=f"{id}-ObjectHandler-v{__version_major__}",
            environment={
                "S3_BUCKET_NAME": bucket.bucket_name,
                "OPENAPI_HTML_DOCUMENT": openapi_html_document,
                "OPENAPI_JSON_DOCUMENT": openapi_json_document,
                "OPENAPI_YAML_DOCUMENT": openapi_yaml_document,
                "API_GATEWAY_URL": core.Fn.import_value(apigw_url_export)
            },
            initial_policy=[
                iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                    actions=["s3:GetObject"],
                                    resources=[f"{bucket.bucket_arn}/*"]),
            ],
            layers=[videon_shared_layer],
            log_retention=cw_logs.RetentionDays.THREE_MONTHS,
            # Lambda Integration in APIGW has a 29 second max timeout.
            timeout=core.Duration.seconds(30),
            tracing=aws_lambda.Tracing.ACTIVE)

        # Grant the API Gateway permission to invoke this Lambda.
        object_handler.add_permission(
            "ObjectHandlerInvoke",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_arn=f"{apigw_restapi.arn_for_execute_api()}")


def filterobj(node, filter_regex):
    """ Take the incoming object (list, dict, etc.) and filter out any
    elements that match the provided regex.  Intended to be used to
    strip internal-only information from our OpenAPI documentation
    before publishing publicly.
    """
    if isinstance(node, dict):
        retval = {}
        for key in node:
            if isinstance(node[key], (dict,list)) \
            and not re.search(filter_regex, key):
                child = filterobj(node[key], filter_regex)
                if child:
                    retval[key] = child
            elif not re.search(filter_regex, key):
                retval[key] = copy.copy(node[key])
        if retval:
            return retval
        else:
            return None
    elif isinstance(node, list):
        retval = []
        for entry in node:
            child = filterobj(entry, filter_regex)
            if child:
                retval.append(child)
        if retval:
            return retval
        else:
            return None
    elif isinstance(node, str):
        if re.search(filter_regex, node):
            return None
        else:
            return node
    else:
        return node
