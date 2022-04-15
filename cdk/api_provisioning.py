"""CDK Stack - Videon Cloud Platform REST API (Provisioning)

This stack provides the implementation for the /provisioning portion of our
REST API, including any sub-paths (e.g. /provisioning/accept).

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
from os import path

from aws_cdk import (aws_dynamodb as dynamodb, aws_iam as iam, aws_lambda,
                     aws_logs as cw_logs, aws_secretsmanager as secretsmanager,
                     core)

# Read the project version number from canonical source in version.py
# Available as __version__.
# Set a placeholder value to stop warnings about undefined variables.
__version__ = "See version.py"
__version_major__ = "See version.py"
exec(open("./version.py").read())  # pylint: disable=exec-used


class ApiProvisioningStack(core.Stack):
    """CDK Stack Class

    Requires the following parameters:
        apigw_restapi: SpecRestApi construct from the core API stack
        videon_internal_auth_arn: ARN of Secrets Manager entry for the internal
            auth secret, needed to call other REST APIs.
    """

    def __init__(self, scope: core.Construct, id: str, iot_device_policy_name,
                 apigw_restapi, videon_internal_auth_arn, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        #######################################################################
        # BACK-END INFRASTRUCTURE
        # Declare any supporting resources for this API route, such as DynamoDB
        # tables and S3 buckets here.
        #######################################################################

        provisioning_requests = dynamodb.Table(  # pylint: disable=unexpected-keyword-arg
            self,
            "ProvisioningRequests",
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery=True,
            partition_key=dynamodb.Attribute(
                name="mac_address", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="serial_number",
                                        type=dynamodb.AttributeType.STRING))

        # Create a secret to be used for provisioning devices
        videon_provisioning_secret = secretsmanager.Secret(
            self,
            "VideonProvisioningSecret",
            description="Provisioning Token for device provisioning",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                exclude_punctuation=True, password_length=32))
        self.videon_provisioning_arn = (
            videon_provisioning_secret.secret_full_arn)

        # Storing the root cert here for now to be used as an env variable
        # in the lambda
        # TODO: move this to an S3 bucket or something so it can be
        # updated when it changes
        amazon_cert_file_path = path.dirname(path.dirname(__file__)) + "/assets"
        with open(path.join(amazon_cert_file_path,
                            "AmazonRootCA1.pem")) as file:
            amazon_root_certificate = file.read()

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

        lambda_environment = {
            "PROVISIONING_REQ_TABLE_NAME": provisioning_requests.table_name,
            "IOT_DEVICE_POLICY_NAME": iot_device_policy_name,
            "VIDEON_PROVISIONING_ARN": self.videon_provisioning_arn,
            "VIDEON_INTERNAL_AUTH_ARN": videon_internal_auth_arn,
            "RESTAPI_URL_PATH": apigw_restapi.url_for_path("/"),
            "AMAZON_ROOT_CERT_VALUE": amazon_root_certificate
        }

        common_lambda_iam_policy = [
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=["secretsmanager:GetSecretValue"],
                                resources=[videon_internal_auth_arn,
                                           self.videon_provisioning_arn]),
        ]

        # Set up secret rotation
        videon_provisioning_secret_rotator = aws_lambda.Function(
            self,
            "VideonProvisioningSecretRotator",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="provisioning_secret_rotator.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api_provisioning"),
            description="Rotates the Secrets Manager secret "
            f"{videon_provisioning_secret.secret_name}",
            environment=lambda_environment,
            initial_policy=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "secretsmanager:DescribeSecret",
                        "secretsmanager:GetSecretValue",
                        "secretsmanager:PutSecretValue",
                        "secretsmanager:UpdateSecretVersionStage"
                    ],
                    resources=[self.videon_provisioning_arn]),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["secretsmanager:GetRandomPassword"],
                    resources=["*"])
            ],
            layers=[videon_shared_layer],
            log_retention=cw_logs.RetentionDays.THREE_MONTHS,
            timeout=core.Duration.seconds(300))

        # Grant Secrets Manager permission to call the Lambda,
        grant = videon_provisioning_secret_rotator.grant_invoke(
            iam.ServicePrincipal("secretsmanager.amazonaws.com"))

        # Rotate the secret every day
        rotation_schedule = videon_provisioning_secret.add_rotation_schedule(
            "VideonProvisioningSecretSchedule",
            rotation_lambda=videon_provisioning_secret_rotator,
            automatically_after=core.Duration.days(1))

        # Ensure the invoke permission is granted before we create the
        # rotation schedule. Otherwise, the CDK deploy may randomly fail here.
        grant.apply_before(rotation_schedule)

        # Create IAM policy
        authorize_iam_policy = [
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=[
                                    "dynamodb:PutItem",
                                ],
                                resources=[provisioning_requests.table_arn]),
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=[
                                    "iot:ListThings",
                                ],
                                resources=["*"])
        ]
        authorize_iam_policy.extend(common_lambda_iam_policy)

        # This function handles operations for the authorize endpoint
        authorize_handler = aws_lambda.Function(
            self,
            "AuthorizeHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="authorize.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api_provisioning"),
            description="Request Handler for /provisioning/authorize API Route",
            # Since this Lambda function is referenced in the OpenAPI
            # definition, we must have a fixed name.  Include version_major
            # in case we need to run multiple versions of the API
            # side-by-side.
            function_name=f"{id}-AuthorizeHandler-v{__version_major__}",
            environment=lambda_environment,
            initial_policy=authorize_iam_policy,
            layers=[videon_shared_layer],
            log_retention=cw_logs.RetentionDays.THREE_MONTHS,
            # Lambda Integration in APIGW has a 29 second max timeout.
            timeout=core.Duration.seconds(30),
            tracing=aws_lambda.Tracing.ACTIVE)

        # Grant the API Gateway permission to invoke this Lambda.
        authorize_handler.add_permission(
            "AuthorizeHandlerInvoke",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_arn=f"{apigw_restapi.arn_for_execute_api()}")

        # Create IAM policy
        request_iam_policy = [
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=[
                                    "dynamodb:DeleteItem",
                                    "dynamodb:GetItem"
                                ],
                                resources=[provisioning_requests.table_arn]),
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=[
                                    "iot:ListThings",
                                    "iot:ListThingPrincipals",
                                    "iot:CreateKeysAndCertificate",
                                    "iot:CreateThing",
                                    "iot:AttachThingPrincipal",
                                    "iot:AttachPolicy",
                                    "iot:DetachThingPrincipal",
                                    "iot:DetachPolicy",
                                    "iot:UpdateCertificate",
                                    "iot:DeleteCertificate",
                                    "iot:DeleteThing",
                                ],
                                resources=["*"])
        ]
        request_iam_policy.extend(common_lambda_iam_policy)

        # This function handles operations for the request endpoint
        request_handler = aws_lambda.Function(
            self,
            "RequestHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="request.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api_provisioning"),
            description=
            "Request Handler for /api_provisioning/request API Route",
            # Since this Lambda function is referenced in the OpenAPI
            # definition, we must have a fixed name.  Include version_major
            # in case we need to run multiple versions of the API
            # side-by-side.
            function_name=f"{id}-RequestHandler-v{__version_major__}",
            environment=lambda_environment,
            initial_policy=request_iam_policy,
            layers=[videon_shared_layer],
            log_retention=cw_logs.RetentionDays.THREE_MONTHS,
            # Lambda Integration in APIGW has a 29 second max timeout.
            timeout=core.Duration.seconds(30),
            tracing=aws_lambda.Tracing.ACTIVE)

        # Grant the API Gateway permission to invoke this Lambda.
        request_handler.add_permission(
            "RequestHandlerInvoke",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_arn=f"{apigw_restapi.arn_for_execute_api()}")
