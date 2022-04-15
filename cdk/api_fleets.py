"""CDK Stack - Videon Cloud Platform REST API (Fleets)

This stack provides the implementation for the /fleets portion of our REST API,
as well as any sub-paths (e.g. /fleets/{fleet_guid}).

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

from aws_cdk import (aws_dynamodb as dynamodb, aws_iam as iam, aws_lambda,
                     aws_logs as cw_logs, core)

# Read the project version number from canonical source in version.py
# Available as __version__.
# Set a placeholder value to stop warnings about undefined variables.
__version__ = "See version.py"
__version_major__ = "See version.py"
exec(open("./version.py").read())  # pylint: disable=exec-used


class ApiFleetsStack(core.Stack):
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

        # Primary way to find a fleet is via the GUID.
        # Add a secondary index so we can look up the GUID from fleet
        # name. Since DynamoDB is case-sensitive, we will store the fleet name
        # as a "search key" all lowercase with no whitespace or non-alphanumeric
        # characters. We will also store the full un-collapsed name in a
        # non-index column.
        fleets = dynamodb.Table(  # pylint: disable=unexpected-keyword-arg
            self,
            "Fleets",
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery=True,
            partition_key=dynamodb.Attribute(
                name="fleet_guid", type=dynamodb.AttributeType.STRING))

        fleets.add_global_secondary_index(
            index_name="fleet_search_key",
            projection_type=dynamodb.ProjectionType.ALL,
            partition_key=dynamodb.Attribute(
                name="fleet_search_key", type=dynamodb.AttributeType.STRING))

        # Table is needed to keep track of fleet <> organization and
        # fleet <> users relationships (users directly assigned to fleets).
        # Creating a single table will allow for more efficient searches
        # with the one-to-many relationships
        fleet_org_users = dynamodb.Table(  # pylint: disable=unexpected-keyword-arg
            self,
            "FleetOrgUsers",
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery=True,
            partition_key=dynamodb.Attribute(
                name="fleet_guid", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="member_guid",
                                        type=dynamodb.AttributeType.STRING))

        fleet_org_users.add_global_secondary_index(
            index_name="member_guid",
            projection_type=dynamodb.ProjectionType.ALL,
            partition_key=dynamodb.Attribute(
                name="member_guid", type=dynamodb.AttributeType.STRING))

        # Follow the standard table design for fleet <> devices relationship
        fleet_devices = dynamodb.Table(  # pylint: disable=unexpected-keyword-arg
            self,
            "FleetDevices",
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery=True,
            partition_key=dynamodb.Attribute(
                name="membership_guid", type=dynamodb.AttributeType.STRING))

        fleet_devices.add_global_secondary_index(
            index_name="fleet_guid",
            projection_type=dynamodb.ProjectionType.ALL,
            partition_key=dynamodb.Attribute(
                name="fleet_guid", type=dynamodb.AttributeType.STRING))

        fleet_devices.add_global_secondary_index(
            index_name="device_guid",
            projection_type=dynamodb.ProjectionType.ALL,
            partition_key=dynamodb.Attribute(
                name="device_guid", type=dynamodb.AttributeType.STRING))

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
            "FLEETS_TABLE_NAME":
                fleets.table_name,
            "FLEET_ORG_USERS_TABLE_NAME":
                fleet_org_users.table_name,
            "FLEET_DEVICES_TABLE_NAME":
                fleet_devices.table_name,
            "COGNITO_ORG_MANAGEMENT_GROUP_NAME":
                cognito_organization_management_group.group_name,
            "VIDEON_INTERNAL_AUTH_ARN":
                videon_internal_auth_arn,
            "RESTAPI_URL_PATH":
                apigw_restapi.url_for_path("/"),
        }

        lambda_iam_policy = [
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=["secretsmanager:GetSecretValue"],
                                resources=[videon_internal_auth_arn]),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "dynamodb:DeleteItem", "dynamodb:GetItem",
                    "dynamodb:PutItem", "dynamodb:Query", "dynamodb:Scan",
                    "dynamodb:UpdateItem", "dynamodb:BatchWriteItem"
                ],
                resources=[fleets.table_arn, fleet_org_users.table_arn,
                           fleet_devices.table_arn]),
            # Also add the tables' indices to the policy
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=[
                                    "dynamodb:Query",
                                    "dynamodb:Scan",
                                ],
                                resources=[
                                    f"{fleets.table_arn}/index/*",
                                    f"{fleet_org_users.table_arn}/index/*",
                                    f"{fleet_devices.table_arn}/index/*"
                                ])
        ]

        # This function handles operations on the entire collection (/objects).
        collection_handler = aws_lambda.Function(
            self,
            "CollectionHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="collection.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api_fleets"),
            description="Request Handler for /fleets API Route",
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

        # This function handles operations on a single object
        object_handler = aws_lambda.Function(
            self,
            "ObjectHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="object.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api_fleets"),
            description="Request Handler for /fleets/{fleet_guid} API Route",
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

        # This function handles user membership within a fleet
        user_handler = aws_lambda.Function(
            self,
            "UserHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="users.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api_fleets"),
            description=
            "Request Handler for /fleets/{fleet_guid}/users API Route",
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

        # Grant the API Gateway permission to invoke this Lambda.
        user_handler.add_permission(
            "UserHandlerInvoke",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_arn=f"{apigw_restapi.arn_for_execute_api()}")

        # This function handles device membership within a fleet
        device_handler = aws_lambda.Function(
            self,
            "DeviceHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="devices.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api_fleets"),
            description=
            "Request Handler for /fleets/{fleet_guid}/devices API Route",
            # Since this Lambda function is referenced in the OpenAPI
            # definition, we must have a fixed name.  Include version_major
            # in case we need to run multiple versions of the API
            # side-by-side.
            function_name=f"{id}-DeviceHandler-v{__version_major__}",
            environment=lambda_environment,
            initial_policy=lambda_iam_policy,
            layers=[videon_shared_layer],
            log_retention=cw_logs.RetentionDays.THREE_MONTHS,
            # Lambda Integration in APIGW has a 29 second max timeout.
            timeout=core.Duration.seconds(30),
            tracing=aws_lambda.Tracing.ACTIVE)

        # Grant the API Gateway permission to invoke this Lambda.
        device_handler.add_permission(
            "DeviceHandlerInvoke",
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
            code=aws_lambda.Code.from_asset("lambda/api_fleets"),
            description=("Request Handler for /fleets/{fleet_guid}/events "
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
