"""CDK Construct - IoT Policy Resource

This construct provides the ability to define an IOT policy that can
be updated using the versioning provided in the Management Console.

See
https://github.com/aws-cloudformation/cloudformation-coverage-roadmap/issues/469
https://medium.com/cyberark-engineering/advanced-custom-resources-with-aws-cdk-1e024d4fb2fa
"""

import json
from typing import Any

from aws_cdk import (aws_logs as cw_logs, aws_iam as iam, aws_lambda, core)
from aws_cdk.core import Duration, RemovalPolicy, Stack
from aws_cdk.custom_resources import Provider


class IotPolicyResource(core.Construct):
    """
    Arguments:
        :param policy_name - The IoT Policy name which needs to be unique in
                             the account
        :param policy_document - the IoT Policy document
        :param timeout: The timeout for the Lambda function implementing this
                        custom resource
    """

    def __init__(self,
                 scope: core.Construct,
                 id: str,
                 policy_name: str,
                 policy_document: Any,
                 timeout: Duration = None) -> None:
        super().__init__(scope, id)

        if isinstance(policy_document, dict):
            policy_document = json.dumps(policy_document)

        account_id = Stack.of(self).account
        region = Stack.of(self).region

        # IMPORTANT! Setting resources to the exact policy name is the most
        # restrictive. But this will cause issues when trying to update
        # the policy name. See this issue for more info:
        #     https://github.com/aws/aws-cdk/issues/14037
        # A possible work around is setting resources to
        # 'arn:aws:iot:{region}:{account_id}:policy/*',
        # which is more permissive.
        lambda_role = iam.Role(
            scope=self,
            id="LambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            inline_policies={
                "IotPolicyProvisioningPolicy":
                    iam.PolicyDocument(statements=[
                        iam.PolicyStatement(
                            actions=[
                                "iot:ListPolicyVersions", "iot:CreatePolicy",
                                "iot:CreatePolicyVersion", "iot:DeletePolicy",
                                "iot:DeletePolicyVersion"
                            ],
                            resources=[
                                f"arn:aws:iot:{region}:{account_id}:policy/*"
                            ],
                            effect=iam.Effect.ALLOW,
                        )
                    ])
            },
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole")
            ],
        )

        if not timeout:
            timeout = Duration.minutes(5)

        event_handler = aws_lambda.Function(
            scope=self,
            id="EventHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            code=aws_lambda.Code.from_asset("lambda/iot"),
            description="Event Handler for custom IoT Policy",
            log_retention=cw_logs.RetentionDays.THREE_MONTHS,
            handler="iot_policy.on_event",
            role=lambda_role,
            timeout=timeout,
        )

        provider = Provider(scope=self,
                            id="Provider",
                            on_event_handler=event_handler)

        core.CustomResource(
            scope=self,
            id="IotPolicy",
            service_token=provider.service_token,
            removal_policy=RemovalPolicy.DESTROY,
            resource_type="Custom::IotPolicy",
            properties={
                "policy_name": policy_name,
                "policy_document": policy_document,
            },
        )
