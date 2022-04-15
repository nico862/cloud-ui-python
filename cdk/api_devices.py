"""CDK Stack - Videon Cloud Platform REST API (Devices)

This stack provides the implementation for the /devices portion of our REST API,
as well as any sub-paths (e.g. /devices/{device_guid}).

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
import json

from aws_cdk import (aws_dynamodb as dynamodb, aws_logs as cw_logs, aws_iam as
                     iam, aws_lambda, core)

# Read the project version number from canonical source in version.py
# Available as __version__.
# Set a placeholder value to stop warnings about undefined variables.
__version__ = "See version.py"
__version_major__ = "See version.py"
exec(open("./version.py").read())  # pylint: disable=exec-used

# device.app.videoncloud.com
# Use this for the custom domain mapping and DNS entries.
IOT_ENDPOINT_HOST_NAME = "device"


class ApiDevicesStack(core.Stack):
    """CDK Stack Class

    Requires the following parameters:
        apigw_restapi: SpecRestApi construct from the core API stack
        videon_internal_auth_arn: ARN of Secrets Manager entry for the internal
            auth secret, needed to call other REST APIs.
    """

    def __init__(self, scope: core.Construct, id: str,
                 cognito_organization_management_group,
                 cognito_device_management_group, apigw_restapi,
                 videon_internal_auth_arn, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        #######################################################################
        # BACK-END INFRASTRUCTURE
        # Declare any supporting resources for this API route, such as DynamoDB
        # tables and S3 buckets here.
        #######################################################################

        self.device_state_table = dynamodb.Table(  # pylint: disable=unexpected-keyword-arg
            self,
            "DeviceState",
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery=True,
            partition_key=dynamodb.Attribute(
                name="device_guid", type=dynamodb.AttributeType.STRING),
            stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES)

        self.device_org_table = dynamodb.Table(  # pylint: disable=unexpected-keyword-arg
            self,
            "DeviceOrg",
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery=True,
            partition_key=dynamodb.Attribute(
                name="device_guid", type=dynamodb.AttributeType.STRING))

        self.device_org_table.add_global_secondary_index(
            index_name="org_guid",
            projection_type=dynamodb.ProjectionType.ALL,
            partition_key=dynamodb.Attribute(
                name="org_guid", type=dynamodb.AttributeType.STRING))

        self.device_events_table = dynamodb.Table(  # pylint: disable=unexpected-keyword-arg
            self,
            "DeviceEvents",
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery=True,
            partition_key=dynamodb.Attribute(
                name="device_guid", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="timestamp",
                                        type=dynamodb.AttributeType.STRING),
            time_to_live_attribute="expires")

        self.device_events_table.add_global_secondary_index(
            index_name="date",
            projection_type=dynamodb.ProjectionType.ALL,
            partition_key=dynamodb.Attribute(
                name="date", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="timestamp",
                                        type=dynamodb.AttributeType.STRING))

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
            "DEVICE_STATE_TABLE_NAME":
                self.device_state_table.table_name,
            "DEVICE_ORG_TABLE_NAME":
                self.device_org_table.table_name,
            "DEVICE_EVENTS_TABLE_NAME":
                self.device_events_table.table_name,
            "COGNITO_ORG_MANAGEMENT_GROUP_NAME":
                cognito_organization_management_group.group_name,
            "COGNITO_DEVICE_MANAGEMENT_GROUP_NAME":
                cognito_device_management_group.group_name,
            "VIDEON_INTERNAL_AUTH_ARN":
                videon_internal_auth_arn,
            "RESTAPI_URL_PATH":
                apigw_restapi.url_for_path("/"),
        }

        common_lambda_iam_policy = [
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=["secretsmanager:GetSecretValue"],
                                resources=[videon_internal_auth_arn]),
        ]

        # Create the restricted IAM policy
        collection_iam_policy = [
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:Query"],
                resources=[self.device_org_table.table_arn + "/index/*"]),
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=["iot:DescribeThing"],
                                resources=["*"]),
        ]
        collection_iam_policy.extend(common_lambda_iam_policy)

        collection_handler = aws_lambda.Function(
            self,
            "CollectionHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="collection.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api_devices"),
            description="Request Handler for /devices API Route",
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

        # Create the restricted IAM policy
        object_iam_policy = [
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:DeleteItem", "dynamodb:GetItem"],
                resources=[self.device_org_table.table_arn]),
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=["iot:DescribeThing"],
                                resources=["*"]),
        ]
        object_iam_policy.extend(common_lambda_iam_policy)

        object_handler = aws_lambda.Function(
            self,
            "ObjectHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="object.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api_devices"),
            description="Request Handler for /devices/{device_guid} API Route",
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

        # Create the restricted IAM policy
        adopt_iam_policy = [
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=["dynamodb:PutItem"],
                                resources=[self.device_org_table.table_arn]),
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=["iot:ListThings"],
                                resources=["*"])
        ]
        adopt_iam_policy.extend(common_lambda_iam_policy)

        adopt_handler = aws_lambda.Function(
            self,
            "AdoptHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="adopt.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api_devices"),
            description="Request Handler for /devices/adopt API Route",
            # Since this Lambda function is referenced in the OpenAPI
            # definition, we must have a fixed name.  Include version_major
            # in case we need to run multiple versions of the API
            # side-by-side.
            function_name=f"{id}-AdoptHandler-v{__version_major__}",
            environment=lambda_environment,
            initial_policy=adopt_iam_policy,
            layers=[videon_shared_layer],
            log_retention=cw_logs.RetentionDays.THREE_MONTHS,
            # Lambda Integration in APIGW has a 29 second max timeout.
            timeout=core.Duration.seconds(30),
            tracing=aws_lambda.Tracing.ACTIVE)

        # Grant the API Gateway permission to invoke this Lambda.
        adopt_handler.add_permission(
            "AdoptHandlerInvoke",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_arn=f"{apigw_restapi.arn_for_execute_api()}")

        # Create the restricted IAM policy
        state_iam_policy = [
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=[
                                    "dynamodb:GetItem",
                                ],
                                resources=[self.device_state_table.table_arn]),
        ]
        state_iam_policy.extend(common_lambda_iam_policy)

        state_handler = aws_lambda.Function(
            self,
            "StateHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="state.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api_devices"),
            description=
            "Request Handler for /devices/{device_guid}/state API Route",
            # Since this Lambda function is referenced in the OpenAPI
            # definition, we must have a fixed name.  Include version_major
            # in case we need to run multiple versions of the API
            # side-by-side.
            function_name=f"{id}-StateHandler-v{__version_major__}",
            environment=lambda_environment,
            initial_policy=state_iam_policy,
            layers=[videon_shared_layer],
            log_retention=cw_logs.RetentionDays.THREE_MONTHS,
            # Lambda Integration in APIGW has a 29 second max timeout.
            timeout=core.Duration.seconds(30),
            tracing=aws_lambda.Tracing.ACTIVE)

        # Grant the API Gateway permission to invoke this Lambda.
        state_handler.add_permission(
            "StateHandlerInvoke",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_arn=f"{apigw_restapi.arn_for_execute_api()}")

        # Create the restricted IAM policy
        metrics_iam_policy = [
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=["cloudwatch:GetMetricData"],
                                resources=["*"])
        ]
        metrics_iam_policy.extend(common_lambda_iam_policy)

        metrics_handler = aws_lambda.Function(
            self,
            "MetricsHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="metrics.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api_devices"),
            description=("Request Handler for /devices/metrics and "
                         "/devices/{device_guid}/metrics API Routes"),
            # Since this Lambda function is referenced in the OpenAPI
            # definition, we must have a fixed name.  Include version_major
            # in case we need to run multiple versions of the API
            # side-by-side.
            function_name=f"{id}-MetricsHandler-v{__version_major__}",
            environment=lambda_environment,
            initial_policy=metrics_iam_policy,
            layers=[videon_shared_layer],
            log_retention=cw_logs.RetentionDays.THREE_MONTHS,
            # Lambda Integration in APIGW has a 29 second max timeout.
            timeout=core.Duration.seconds(30),
            tracing=aws_lambda.Tracing.ACTIVE)

        # Grant the API Gateway permission to invoke this Lambda.
        metrics_handler.add_permission(
            "MetricsHandlerInvoke",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_arn=f"{apigw_restapi.arn_for_execute_api()}")

        # Create the restricted IAM policy
        events_iam_policy = [
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=["dynamodb:Query"],
                                resources=[self.device_events_table.table_arn]),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:Query"],
                resources=[f"{self.device_events_table.table_arn}/index/*"])
        ]
        events_iam_policy.extend(common_lambda_iam_policy)

        events_handler = aws_lambda.Function(
            self,
            "EventsHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="events.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api_devices"),
            description=("Request Handler for /devices/events and "
                         "/devices/{device_guid}/events API Routes"),
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

        # Create a lambda that watches for changes on the device state table
        state_change_iam_policy = [
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=["dynamodb:PutItem"],
                                resources=[self.device_events_table.table_arn]),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "dynamodb:GetRecords", "dynamodb:GetShardIterator",
                    "dynamodb:DescribeStream", "dynamodb:ListStreams"
                ],
                resources=[f"{self.device_state_table.table_arn}/stream/*"])
        ]

        state_change_event_handler = aws_lambda.Function(
            self,
            "StateChangeEventHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="state_change.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/device_event_handlers"),
            description="Event Handler for device state changes",
            function_name=f"{id}-StateChangeEventHandler-v{__version_major__}",
            environment=lambda_environment,
            initial_policy=state_change_iam_policy,
            layers=[videon_shared_layer],
            log_retention=cw_logs.RetentionDays.THREE_MONTHS,
            timeout=core.Duration.seconds(30),
            tracing=aws_lambda.Tracing.ACTIVE)

        aws_lambda.CfnEventSourceMapping(
            self,
            "StateChangeEventSourceMapping",
            function_name=state_change_event_handler.function_arn,
            event_source_arn=self.device_state_table.table_stream_arn,
            filter_criteria=aws_lambda.CfnEventSourceMapping.
            FilterCriteriaProperty(filters=[
                aws_lambda.CfnEventSourceMapping.FilterProperty(
                    pattern=json.dumps({"eventName": ["MODIFY", "INSERT"]}))
            ]),
            maximum_record_age_in_seconds=3600,
            maximum_retry_attempts=2,
            starting_position="TRIM_HORIZON")
