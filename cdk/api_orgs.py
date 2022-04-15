"""CDK Stack - Videon Cloud Platform REST API (Organizations)

This stack provides the implementation for the /orgs portion of our REST API,
as well as any sub-paths (e.g. /orgs/{org_guid}).

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

from aws_cdk import (
    aws_dynamodb as dynamodb,
    aws_iam as iam,
    aws_lambda,  # lambda is a reserved word in Python, so use orig package name
    aws_logs as cw_logs,
    core)

# Read the project version number from canonical source in version.py
# Available as __version__.
# Set a placeholder value to stop warnings about undefined variables.
__version__ = "See version.py"
__version_major__ = "See version.py"
exec(open("./version.py").read())  # pylint: disable=exec-used


class ApiOrgsStack(core.Stack):
    """CDK Stack Class

    Requires the following parameters:
        cognito_organization_management_group: Group Name (CognitoStack)
        apigw_restapi: SpecRestApi construct from the core API stack
        videon_internal_auth_arn: ARN of Secrets Manager entry for the internal
            auth secret, needed to call other REST APIs.
    """

    def __init__(self, scope: core.Construct, id: str,
                 cognito_organization_management_group, apigw_restapi,
                 videon_internal_auth_arn, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        #######################################################################
        # BACK-END INFRASTRUCTURE
        # Declare any supporting resources for this API route, such as DynamoDB
        # tables and S3 buckets here.
        #######################################################################

        # Primary way to find a corporation is via the GUID.
        # Add a secondary index so we can look up the GUID from corporation
        # name.  Since DynamoDB is case-sensitive, we will store the org name as
        # a "search key" all lowercase with no whitespace or non-alphanumeric
        # characters.  We will also store the full un-collapsed name in a
        # non-index column.
        organizations = dynamodb.Table(  # pylint: disable=unexpected-keyword-arg
            self,
            "Organizations",
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery=True,
            partition_key=dynamodb.Attribute(
                name="org_guid", type=dynamodb.AttributeType.STRING))

        organizations.add_global_secondary_index(
            index_name="org_search_key",
            projection_type=dynamodb.ProjectionType.ALL,
            partition_key=dynamodb.Attribute(
                name="org_search_key", type=dynamodb.AttributeType.STRING))

        # Provide a table to quickly look up org and user membership.
        # We will need to get a list of users in an org, and also what orgs
        # a user belongs to.  So we will need indexes for each one.
        # Since the primary index must be unique, we cannot use either user
        # or org guid as the primary key.  To satisfy the uniqueness
        # constraint, we will use a guid as the primary key with a throw-away
        # value.
        org_users = dynamodb.Table(  # pylint: disable=unexpected-keyword-arg
            self,
            "OrgUsers",
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery=True,
            partition_key=dynamodb.Attribute(
                name="membership_guid", type=dynamodb.AttributeType.STRING))

        org_users.add_global_secondary_index(
            index_name="org_guid",
            projection_type=dynamodb.ProjectionType.ALL,
            partition_key=dynamodb.Attribute(
                name="org_guid", type=dynamodb.AttributeType.STRING))

        org_users.add_global_secondary_index(
            index_name="user_guid",
            projection_type=dynamodb.ProjectionType.ALL,
            partition_key=dynamodb.Attribute(
                name="user_guid", type=dynamodb.AttributeType.STRING))

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
            "ORGANIZATIONS_TABLE_NAME": organizations.table_name,
            "ORG_USERS_TABLE_NAME": org_users.table_name,
            "COGNITO_ORG_MANAGEMENT_GROUP_NAME":
                cognito_organization_management_group.group_name,
            "VIDEON_INTERNAL_AUTH_ARN": videon_internal_auth_arn,
            "RESTAPI_URL_PATH": apigw_restapi.url_for_path("/"),
        }

        lambda_iam_policy = [
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=["secretsmanager:GetSecretValue"],
                                resources=[videon_internal_auth_arn]),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "dynamodb:DeleteItem",
                    "dynamodb:GetItem",
                    "dynamodb:PutItem",
                    "dynamodb:Query",
                    "dynamodb:Scan",
                    "dynamodb:UpdateItem",
                    "dynamodb:BatchWriteItem"
                ],
                resources=[org_users.table_arn, organizations.table_arn]),
            # Also add the tables' indices to the policy
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                    actions=[
                        "dynamodb:Query",
                        "dynamodb:Scan",
                    ],
                    resources=[f"{org_users.table_arn}/index/*",
                               f"{organizations.table_arn}/index/*"])
        ]

        # This function handles operations on the entire collection (/objects).
        collection_handler = aws_lambda.Function(
            self,
            "CollectionHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="collection.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api_orgs"),
            description="Request Handler for /orgs API Route",
            # Since this Lambda function is referenced in the OpenAPI
            # definition, we must have a fixed name.  Include version_major
            # in case we need to run multiple versions of the API
            # side-by-side.
            function_name=f"{id}-CollectionHandler-v{__version_major__}",
            environment=lambda_environment,
            initial_policy=lambda_iam_policy,
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

        # This function handles operations on the singular objects
        # (/objects/object_guid).
        object_handler = aws_lambda.Function(
            self,
            "ObjectHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="object.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api_orgs"),
            description="Request Handler for /orgs/org_guid API Route",
            # Since this Lambda function is referenced in the OpenAPI
            # definition, we must have a fixed name.  Include version_major
            # in case we need to run multiple versions of the API
            # side-by-side.
            function_name=f"{id}-ObjectHandler-v{__version_major__}",
            environment=lambda_environment,
            initial_policy=lambda_iam_policy,
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

        # This function handles operations dealing with user membership in
        # organizations.
        user_handler = aws_lambda.Function(
            self,
            "UserHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="users.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api_orgs"),
            description="Request Handler for /orgs/{ org_guid }/users route",
            # Since this Lambda function is referenced in the OpenAPI
            # definition, we must have a fixed name.  Include version_major
            # in case we need to run multiple versions of the API
            # side-by-side.
            function_name=f"{id}-UserHandler-v{__version_major__}",
            environment=lambda_environment,
            initial_policy=lambda_iam_policy,
            layers=[videon_shared_layer],
            log_retention=cw_logs.RetentionDays.THREE_MONTHS,
            # Lambda Integration in APIGW has a 29 second max timeout.
            timeout=core.Duration.seconds(30),
            tracing=aws_lambda.Tracing.ACTIVE)

        user_handler.add_permission(
            "UserHandlerInvoke",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_arn=f"{apigw_restapi.arn_for_execute_api()}")

        # Create the restricted IAM policy
        events_iam_policy = [
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=["secretsmanager:GetSecretValue"],
                                resources=[videon_internal_auth_arn]),
        ]

        events_handler = aws_lambda.Function(
            self,
            "EventsHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="events.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api_orgs"),
            description=("Request Handler for /orgs/{org_guid}/events "
                         "API Route"),
            # Since this Lambda function is referenced in the OpenAPI
            # definition, we must have a fixed name.  Include version_major
            # in case we need to run multiple versions of the API
            # side-by-side.
            function_name=f"{id}-EventsHandler-v{__version_major__}",
            environment=lambda_environment,
            initial_policy=events_iam_policy,
            layers=[videon_shared_layer],
            log_retention=cw_logs.RetentionDays.THREE_MONTHS,
            # Lambda Integration in APIGW has a 29 second max timeout.
            timeout=core.Duration.seconds(30),
            tracing=aws_lambda.Tracing.ACTIVE)

        # Grant the API Gateway permission to invoke this Lambda.
        events_handler.add_permission(
            "EventsHandlerInvoke",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_arn=f"{apigw_restapi.arn_for_execute_api()}")
