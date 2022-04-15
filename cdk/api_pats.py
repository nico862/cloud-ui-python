"""CDK Stack - Videon Cloud Platform REST API (Personal Access Tokens)

This stack provides the implementation for the /pats portion of our REST API,
as well as any sub-paths (e.g. /pats/{token_guid}).

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

from aws_cdk import (aws_dynamodb as dynamodb, aws_logs as cw_logs, aws_iam as
                     iam, aws_lambda, core)

# Read the project version number from canonical source in version.py
# Available as __version__.
# Set a placeholder value to stop warnings about undefined variables.
__version__ = "See version.py"
__version_major__ = "See version.py"
exec(open("./version.py").read())  # pylint: disable=exec-used


class ApiPatsStack(core.Stack):
    """CDK Stack Class

    Requires the following parameters:
        apigw_restapi: SpecRestApi construct from the core API stack
        cognito_user_management_group: Group Name (CognitoStack)
        videon_internal_auth_arn: ARN of Secrets Manager entry for the internal
            auth secret, needed to call other REST APIs.
    """

    def __init__(self, scope: core.Construct, id: str, apigw_restapi,
                 cognito_user_management_group, videon_internal_auth_arn,
                 **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        #######################################################################
        # BACK-END INFRASTRUCTURE
        # Declare any supporting resources for this API route, such as DynamoDB
        # tables and S3 buckets here.
        #######################################################################

        # Create the table, using the SHA256 of the token as a primary key
        tokens = dynamodb.Table(  # pylint: disable=unexpected-keyword-arg
            self,
            "PersonalAccessTokens",
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery=True,
            partition_key=dynamodb.Attribute(
                name="token_guid", type=dynamodb.AttributeType.STRING))

        # We will be searching via token_hash a lot so add that as a
        # global secondary index
        tokens.add_global_secondary_index(
            index_name="token_hash",
            projection_type=dynamodb.ProjectionType.ALL,
            partition_key=dynamodb.Attribute(
                name="token_hash", type=dynamodb.AttributeType.STRING))

        # We will be searching via user_guid a lot so add that as a
        # global secondary index
        tokens.add_global_secondary_index(
            index_name="user_guid",
            projection_type=dynamodb.ProjectionType.ALL,
            partition_key=dynamodb.Attribute(
                name="user_guid", type=dynamodb.AttributeType.STRING))

        # Uncomment once email reminders are implemented
        # Since we will be checking for expired tokens daily, adding
        # a GSI on the expires timestamp with a sort key on the token
        # hash (which will be removed once a token has expired), allows
        # us to create a sparse index [1] for more efficient searches
        # [1]:
        # https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/bp-indexes-general-sparse-indexes.html
        # tokens.add_global_secondary_index(
        #     index_name="expires",
        #     # TODO: only need to project columns needed for email reminders
        #     projection_type=dynamodb.ProjectionType.ALL,
        #     partition_key=dynamodb.Attribute(
        #         name="expires", type=dynamodb.AttributeType.STRING),
        #     sort_key=dynamodb.Attribute(name="token_hash",
        #                                 type=dynamodb.AttributeType.STRING))

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
            "PERSONAL_ACCESS_TOKENS_TABLE_NAME": tokens.table_name,
            "VIDEON_INTERNAL_AUTH_ARN": videon_internal_auth_arn,
            "RESTAPI_URL_PATH": apigw_restapi.url_for_path("/"),
            "COGNITO_USER_MANAGEMENT_GROUP_NAME":
                    cognito_user_management_group.group_name,
        }

        common_lambda_iam_policy = [
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=["secretsmanager:GetSecretValue"],
                                resources=[videon_internal_auth_arn]),
        ]

        collection_iam_policy = [
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=[
                                    "dynamodb:PutItem",
                                    "dynamodb:UpdateItem",
                                    "dynamodb:DeleteItem",
                                ],
                                resources=[tokens.table_arn]),
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                    actions=[
                        "dynamodb:Query",
                    ],
                    resources=[tokens.table_arn + "/index/*"])
        ]
        collection_iam_policy.extend(common_lambda_iam_policy)

        collection_handler = aws_lambda.Function(
            self,
            "CollectionHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="collection.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api_pats"),
            description="Request Handler for /pats API Route",
            # Since this Lambda function is referenced in the OpenAPI
            # definition, we must have a fixed name.  Include version_major
            # in case we need to run multiple versions of the API
            # side-by-side.
            function_name=f"{id}-CollectionHandler-v{__version_major__}",
            environment=lambda_environment,
            initial_policy=collection_iam_policy,
            layers=[videon_shared_layer],
            log_retention=cw_logs.RetentionDays.THREE_MONTHS,
            # Lambda Integration in APIGW has a 29 second max timeout.
            timeout=core.Duration.seconds(30),
            tracing=aws_lambda.Tracing.ACTIVE)

        # Grant the API Gateway permission to invoke this Lambda.
        collection_handler.add_permission(
            "CollectionHandlerInvoke",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_arn=f"{apigw_restapi.arn_for_execute_api()}")

        object_iam_policy = [
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=[
                                    "dynamodb:DeleteItem",
                                    "dynamodb:GetItem",
                                ],
                                resources=[tokens.table_arn]),
        ]
        object_iam_policy.extend(common_lambda_iam_policy)

        # This function handles operations on the singular objects
        # (/objects/object_guid).
        object_handler = aws_lambda.Function(
            self,
            "ObjectHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="object.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api_pats"),
            description="Request Handler for /pats/token_guid API Route",
            # Since this Lambda function is referenced in the OpenAPI
            # definition, we must have a fixed name.  Include version_major
            # in case we need to run multiple versions of the API
            # side-by-side.
            function_name=f"{id}-ObjectHandler-v{__version_major__}",
            environment=lambda_environment,
            initial_policy=object_iam_policy,
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
