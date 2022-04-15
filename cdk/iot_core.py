"""CDK Stack - IoT Core

This stack provides the AWS IoT Core infrastructure and rules engine for
devices to connect and push data, receive commands, etc.

This stack interfaces with the api_devices stack, which provides the /devices
REST API routes for the Web application.  Stateful resources used by the REST
API (e.g. a DynamoDB table to track the devices) should be managed in the
api_devices and passed here as a reference.

The resources in this stack should be limited to the IoT Core side of things.
"""

from aws_cdk import (aws_logs as cw_logs, aws_iam as iam, aws_iot as iot,
                     aws_route53 as route53, aws_s3 as s3, custom_resources as
                     cr, core, aws_lambda)
from iot_policy_resource import IotPolicyResource

# Read the project version number from canonical source in version.py
# Available as __version__.
# Set a placeholder value to stop warnings about undefined variables.
__version__ = "See version.py"
__version_major__ = "See version.py"
exec(open("./version.py").read())  # pylint: disable=exec-used

# device.app.videoncloud.com
# Use this for the custom domain mapping and DNS entries.
IOT_ENDPOINT_HOST_NAME = "device"


class IotCoreStack(core.Stack):
    """CDK Stack Class

    Requires the following parameters:
        acm_cert: ACM Certificate Object (Route53AcmStack)
        device_state_table: DynamoDB Table Object (ApiDevicesStack)
        route53_zone_id_export: Cfn Export name for Zone Id (Route53AcmStack)
        route53_zone_name_export: Cfn Export name for Zone Name
    """

    def __init__(self, scope: core.Construct, id: str, acm_cert,
                 device_state_table, route53_zone_id_export,
                 route53_zone_name_export, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        #######################################################################
        # DNS ENDPOINT
        # When dealing with customer corporate IT departments, it is A LOT
        # easier to get them to whitelist device.xxxxx.videoncloud.com than
        # something some-random-name.amazonaws.com.  Anything that CAN be
        # mapped under our domain SHOULD be under our domain.
        #######################################################################

        # Create custom domain config for IoT core so devices connect to
        # device.xxx.videoncloud.com not a1s2d4f5s6d7a8f9a023.amazonaws.com
        domain_config = iot.CfnDomainConfiguration(
            self,
            "VideonDomain",
            domain_configuration_status="ENABLED",
            domain_name=f"{IOT_ENDPOINT_HOST_NAME}."
            f"{core.Fn.import_value(route53_zone_name_export)}",
            server_certificate_arns=[acm_cert.certificate_arn])

        # Get the IoT Endpoint to we can make a DNS alias
        # https://stackoverflow.com/questions/60347716/how-to-get-the-aws-iot-custom-endpoint-in-cdk
        get_iot_endpoint = cr.AwsCustomResource(
            self,
            "IoTEndpoint",
            on_create=cr.AwsSdkCall(
                action="describeEndpoint",
                service="Iot",
                parameters={"endpointType": "iot:Data-ATS"},
                physical_resource_id=cr.PhysicalResourceId.from_response(
                    "endpointAddress")),
            policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
                resources=cr.AwsCustomResourcePolicy.ANY_RESOURCE))
        get_iot_endpoint.node.add_dependency(domain_config)

        # Import the zone using the Id and Name so we can create a DNS record.
        route53_zone = route53.PublicHostedZone.from_hosted_zone_attributes(
            self,
            "PublicHostedZone",
            hosted_zone_id=core.Fn.import_value(route53_zone_id_export),
            zone_name=core.Fn.import_value(route53_zone_name_export))

        route53_cname = route53.CnameRecord(
            self,
            "VideonDomainRecord",
            domain_name=get_iot_endpoint.get_response_field("endpointAddress"),
            zone=route53_zone,
            record_name=IOT_ENDPOINT_HOST_NAME)

        # Export the FQDN of the IoT Endpoint so we can reference it in
        # outputs.json.
        core.CfnOutput(self,
                       "IoTEndpointFqdn",
                       value=route53_cname.domain_name,
                       description="IoT Core DNS Endpoint FQDN",
                       export_name="IoTEndpointFqdn")

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
        # IoT Rules
        # Rules are actions taken in response to certain messages (e.g.
        # insert received message into DynamoDB).
        #
        # For receive-only rules (e.g. device telemetry), use basic ingest to
        # reduce costs.
        # https://docs.aws.amazon.com/iot/latest/developerguide/iot-basic-ingest.html
        #######################################################################

        # Error Action
        # Standardize error handling for our IoT Core rules by logging them to
        # CloudWatch.  This allows us to search the errors and do debugging.
        # In the future, we can create log metrics and trigger alarms from
        # that (e.g. a high number of rule failures).
        # https://docs.aws.amazon.com/iot/latest/developerguide/rule-error-handling.html

        error_action_log_group = cw_logs.LogGroup(
            self, "ErrorLogs", retention=cw_logs.RetentionDays.THREE_MONTHS)

        error_action_role = iam.Role(
            self,
            "ErrorRole",
            assumed_by=iam.ServicePrincipal("iot.amazonaws.com"),
            inline_policies={
                "cloudwatch-logs":
                    iam.PolicyDocument(statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "logs:CreateLogStream", "logs:PutLogEvents"
                            ],
                            resources=[error_action_log_group.log_group_arn])
                    ])
            })

        error_action = iot.CfnTopicRule.ActionProperty(
            cloudwatch_logs=iot.CfnTopicRule.CloudwatchLogsActionProperty(
                log_group_name=error_action_log_group.log_group_name,
                role_arn=error_action_role.role_arn))

        # Catch All Rule
        # This rule merely collects any received messages and dumps them into
        # an S3 bucket for analysis.  This can be useful for debugging device
        # to cloud communication (e.g. malformed MQTT messages being dropped).
        #
        # Note that some messages may not be caught by this rule (e.g. basic
        # ingest).
        #
        # In a high-traffic environment, you may want to disable this to
        # cut costs.
        #
        # PROTIP: If you want to search this bucket, Athena is your friend!

        catch_all_bucket = s3.Bucket(
            self,
            "CatchAllBucket",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            encryption=s3.BucketEncryption.S3_MANAGED,
            lifecycle_rules=[
                s3.LifecycleRule(
                    abort_incomplete_multipart_upload_after=core.Duration.days(
                        90),
                    expiration=core.Duration.days(90))
            ])

        catch_all_role = iam.Role(
            self,
            "CatchAllRole",
            assumed_by=iam.ServicePrincipal("iot.amazonaws.com"),
            inline_policies={
                "s3":
                    iam.PolicyDocument(statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["s3:ListBucket"],
                            resources=[catch_all_bucket.bucket_arn]),
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["s3:PutObject"],
                            resources=[f"{catch_all_bucket.bucket_arn}/*"]),
                    ])
            })

        iot.CfnTopicRule(
            self,
            "CatchAllRule",
            topic_rule_payload=iot.CfnTopicRule.TopicRulePayloadProperty(
                actions=[
                    iot.CfnTopicRule.ActionProperty(
                        s3=iot.CfnTopicRule.S3ActionProperty(
                            bucket_name=catch_all_bucket.bucket_name,
                            key="${topic()}/"
                            "${parse_time('yyyyMMdd-HHmmss-z',timestamp())}/"
                            "${traceid()}",
                            role_arn=catch_all_role.role_arn))
                ],
                sql="SELECT * FROM '#'",
                aws_iot_sql_version="2016-03-23",
                description="Log all messages to S3 for debugging",
                error_action=error_action,
                rule_disabled=False),
            rule_name="catch_all")

        # Device State
        # $aws/rules/device_state/device_guid
        # A periodic message from the device with non-metric info like IP
        # address, last reboot time, version info, etc.  Use basic ingest, and
        # store the received info in a DynamoDB table so /devices REST API
        # route can query it.

        device_state_role = iam.Role(
            self,
            "DeviceStateRole",
            assumed_by=iam.ServicePrincipal("iot.amazonaws.com"),
            inline_policies={
                "dynamodb-putitem":
                    iam.PolicyDocument(statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["dynamodb:PutItem"],
                            resources=[device_state_table.table_arn])
                    ])
            })

        iot.CfnTopicRule(
            self,
            "DeviceStateRule",
            topic_rule_payload=iot.CfnTopicRule.TopicRulePayloadProperty(
                actions=[
                    iot.CfnTopicRule.ActionProperty(
                        dynamo_d_bv2=iot.CfnTopicRule.DynamoDBv2ActionProperty(
                            role_arn=device_state_role.role_arn,
                            put_item=iot.CfnTopicRule.PutItemInputProperty(
                                table_name=device_state_table.table_name)))
                ],
                # TODO: Implement better validation of the message contents to
                # prevent garbage data from getting into the DB, see CP-171.
                #
                # When updating the below statement, make sure the
                # devices/{guid}/state endpoint does not need any changes,
                # and add/remove any changed fields from the OpenAPI definition
                sql="SELECT daemon_version, system_version, firmware_version, "
                    "serial_number, device_guid, mac_address_provisioned, "
                    "web_server_enabled, web_server_pid, "
                    "streamin_daemon_enabled, streamin_daemon_pid, "
                    "ull_server_enabled, ull_server_pid,"
                    "device_name, ip_scheme, mac_address_current, device_ip, "
                    "hostname, host_ip, last_boot, input_video_source, "
                    "input_video_format, input_audio_source, "
                    "input_audio_detected, streaming_output_enabled, "
                    "streaming_output_active, "
                    "timestamp() as last_state_update FROM 'device_state/+' "
                    "WHERE length(topic()) = 49",
                aws_iot_sql_version="2016-03-23",
                description="Periodic messages from device with non-metric "
                "state info using basic ingest",
                error_action=error_action,
                rule_disabled=False),
            # Rule name should be fixed so devices can call it.
            rule_name="device_state")

        # Device Health Metrics
        # Send metrics of that indicate the device's health (CPU, Memory,
        # Temperature, etc.).  Use basic ingest, and store the data in
        # CloudWatch, so we can retrieve it and plot metrics.  Use CloudWatch
        # instead of Timestream so we get built in TTL and downsampling.
        device_health_metrics_role = iam.Role(
            self,
            "DeviceHealthMetricsRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole")
            ],
            inline_policies={
                "cloudwatch-metrics":
                    iam.PolicyDocument(statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["cloudwatch:PutMetricData"],
                            resources=["*"],
                            conditions={
                                "StringLike": {
                                    "cloudwatch:namespace": ["Videon/*"]
                                }
                            })
                    ])
            })

        health_metrics_handler = aws_lambda.Function(
            self,
            "DeviceHealthMetricsHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="put_metrics.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/cloudwatch_metrics"),
            description="Event Handler for post to device_metrics/+ topics",
            role=device_health_metrics_role,
            layers=[videon_shared_layer],
            log_retention=cw_logs.RetentionDays.THREE_MONTHS,
            # Lambda Integration in APIGW has a 29 second max timeout.
            timeout=core.Duration.seconds(30),
            tracing=aws_lambda.Tracing.ACTIVE)

        health_metrics_handler.add_permission(
            id="iot-events",
            principal=iam.ServicePrincipal("iot.amazonaws.com"),
            action="lambda:InvokeFunction")

        iot.CfnTopicRule(
            self,
            "DeviceHealthMetricsRule",
            topic_rule_payload=iot.CfnTopicRule.TopicRulePayloadProperty(
                actions=[
                    iot.CfnTopicRule.ActionProperty(
                        lambda_=iot.CfnTopicRule.LambdaActionProperty(
                            function_arn=health_metrics_handler.function_arn))
                ],
                # TODO: Implement better validation of the message contents to
                # prevent garbage data from getting into the DB, see CP-171.
                sql="SELECT * FROM 'device_metrics/+'",
                aws_iot_sql_version="2016-03-23",
                description="Periodic messages from device with health metrics"
                " using basic ingest",
                error_action=error_action,
                rule_disabled=False),
            # Rule name should be fixed so devices can call it.
            rule_name="device_health_metrics")

        #######################################################################
        # IoT Policies
        # These policies control how the device can connect (what client ID),
        # and what topics is can publish/subscribe to.
        # https://docs.aws.amazon.com/iot/latest/developerguide/iot-policies.html
        #
        # General Guidelines:
        #   - Devices can connect using their own name/guid only
        #   - Devices can publish telemetry using their own name/guid only
        #   - Devices can receive and subscribe to topics that match their
        #     device name/guid, or the guid of the fleet/org they belong to.
        #   - fleet_guid and org_guid must be assigned as attributes to the
        #     device.
        #
        # To avoid tailoring a policy for every device, use policy variables.
        # https://docs.aws.amazon.com/iot/latest/developerguide/thing-policy-variables.html
        #######################################################################

        policy_document = {
            "Version":
                "2012-10-17",
            "Statement": [{
                "Effect":
                    "Allow",
                "Action": ["iot:Connect"],
                "Resource": [
                    f"arn:aws:iot:{self.region}:{self.account}:client"
                    "/${iot:Connection.Thing.ThingName}"
                ]
            }, {
                "Effect":
                    "Allow",
                "Action": ["iot:Publish"],
                "Resource": [
                    f"arn:aws:iot:{self.region}:{self.account}:topic"
                    "/$aws/rules/*/${iot:Connection.Thing.ThingName}"
                ]
            }, {
                "Effect":
                    "Allow",
                "Action": ["iot:Receive"],
                "Resource": [
                    f"arn:aws:iot:{self.region}:{self.account}:topic"
                    "/cmd/videon-cloud/device"
                    "/${iot:Connection.Thing.ThingName}/*",
                    f"arn:aws:iot:{self.region}:{self.account}:topic"
                    "/cmd/videon-cloud/org"
                    "/${iot:Connection.Thing.Attributes[org_guid]}/*",
                    f"arn:aws:iot:{self.region}:{self.account}:topic"
                    "/cmd/videon-cloud/fleet"
                    "/${iot:Connection.Thing.Attributes[fleet_guid]}/*"
                ]
            }, {
                "Effect":
                    "Allow",
                "Action": ["iot:Subscribe"],
                "Resource": [
                    f"arn:aws:iot:{self.region}:{self.account}:topicfilter"
                    "/cmd/videon-cloud/device"
                    "/${iot:Connection.Thing.ThingName}/*",
                    f"arn:aws:iot:{self.region}:{self.account}:topicfilter"
                    "/cmd/videon-cloud/org"
                    "/${iot:Connection.Thing.Attributes[org_guid]}/*",
                    f"arn:aws:iot:{self.region}:{self.account}:topicfilter"
                    "/cmd/videon-cloud/fleet"
                    "/${iot:Connection.Thing.Attributes[fleet_guid]}/*"
                ]
            }, {
                "Effect":
                    "Allow",
                "Action": ["iot:*"],
                "Resource": [
                    f"arn:aws:iot:{self.region}:{self.account}:topic/*"
                ]
            }]
        }

        self.iot_policy_resource_name = "device_policy_dev"
        IotPolicyResource(
            scope=self,
            id="VideonDevicePolicy",
            policy_name=self.iot_policy_resource_name,
            policy_document=policy_document)
