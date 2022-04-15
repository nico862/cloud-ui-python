"""CDK Stack - Videon Cloud Platform REST API (Core Resources)

This stack creates a REST API Gateway itself from our OpenAPI specification,
and creates common resources for the overall API platform
(e.g. authentication/authorization).

Specific API routes/methods/endpoints should be implemented as separate CDK
stacks that reference this one, with a name like api_xxxxx.  Each one of these
stacks should be considered a pseudo-microservice that owns a particular API
route (/device, /user, etc.).  The stacks should be relatively self-contained
and implement their own Lambda function(s), and any stateful resources like
DynamoDB tables or S3 buckets.
"""

import json
from aws_cdk import (aws_logs as cw_logs, aws_apigateway as api_gw, aws_lambda,
                     aws_iam as iam, aws_route53 as route53, aws_route53_targets
                     as targets, aws_secretsmanager as secretsmanager, core)
from prance import ResolvingParser

# Read the project version number from canonical source in version.py
# Available as __version__.
# Set a placeholder value to stop warnings about undefined variables.
__version__ = "See version.py"
__version_major__ = "See version.py"
exec(open("./version.py").read())  # pylint: disable=exec-used

# api.app.videoncloud.com
# Use this for the custom domain mapping and DNS entries.
API_HOST_NAME = "api"

# api.app.videoncloud.com/v1
# Use this for the stage name and base URL mapping.
API_BASE_NAME = f"v{__version_major__}"

# Currently, regional seems to be a better fit.
# Revisit this before we go to prod.
API_ENDPOINT_TYPE = api_gw.EndpointType.REGIONAL


class ApiStack(core.Stack):
    """CDK Stack Class

    Attributes:
        acm_cert: ACM Certificate Object (Route53AcmStack)
        cognito_user_pool: User Pool Object (CognitoStack)
        cognito_user_pool_client: App Client Object (CognitoStack)
        cognito_user_pool_domain: User Pool Domain Object (CognitoStack)
        cognito_global_admins_group: Group Name (CognitoStack)
        cognito_global_users_group: Group Name (CognitoStack)
        cognito_global_readers_group: Group Name (CognitoStack)
        cognito_device_management_group: Group Name (CognitoStack)
        cognito_user_management_group: Group Name (CognitoStack)
        openapi_root_file: Path to the root file of our OpenAPI definition
        route53_zone_id_export: Cfn Export name for Zone Id (Route53AcmStack)
        route53_zone_name_export: Cfn Export name for Zone Name

    The OpenAPI definition can contain $ref entries (our OpenAPI parser can
    resolve references). Note the contents of the OpenAPI definition will be
    fixed up before being applied to the API gateway to substitute in string.

    ACM Certificate and Route53 DNS zone are used to attach a custom domain
    name to the API gateway.  This stack will create the DNS records (e.g.
    api.whatever.videoncloud.com).
    """

    def __init__(self, scope: core.Construct, id: str, acm_cert,
                 cognito_user_pool, cognito_user_pool_client,
                 cognito_user_pool_domain, cognito_global_admins_group,
                 cognito_global_users_group, cognito_global_readers_group,
                 cognito_device_management_group, cognito_user_management_group,
                 openapi_root_file, route53_zone_id_export,
                 route53_zone_name_export, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Export the version string of the API so it shows up in outputs.json.
        # External programs in the pipeline scripts can then reference it
        # (e.g. to generate documentation).
        core.CfnOutput(self,
                       "ApiVersionStr",
                       value=__version__,
                       description="API Version String")

        api_log_group = cw_logs.LogGroup(
            self,
            "VideonRestApiLogs",
            retention=cw_logs.RetentionDays.THREE_MONTHS)

        # Read OpenAPI file(s) and fix it up for our API Gateway
        #
        # We have to use prance's resolving parser because our OpenAPI
        # specification is spread across several files, which AWS cannot
        # import directly.  Prance will assemble this into one file.
        #
        # Also use this as an opportunity to subsitute in the current region
        # and AWS account number.  Our OpenAPI source files should have
        # placeholder values of $REGION and $ACCOUNT.
        openapi_parser = ResolvingParser(openapi_root_file)
        openapi_str = json.dumps(openapi_parser.specification)
        openapi_str = openapi_str.replace("$REGION", self.region)
        openapi_str = openapi_str.replace("$ACCOUNT", self.account)
        self.openapi_obj = json.loads(openapi_str)

        self.rest_api = api_gw.SpecRestApi(
            self,
            "VideonRestApi",
            api_definition=api_gw.ApiDefinition.from_inline(self.openapi_obj),
            deploy=True,
            # pylint chokes on this line and I don't know why
            deploy_options=api_gw.StageOptions( # pylint: disable=unexpected-keyword-arg
                access_log_destination=api_gw.LogGroupLogDestination(
                    api_log_group),
                access_log_format=api_gw.AccessLogFormat.
                json_with_standard_fields(caller=True,
                                          http_method=True,
                                          ip=True,
                                          protocol=True,
                                          request_time=True,
                                          resource_path=True,
                                          response_length=True,
                                          status=True,
                                          user=True),
                description="Major version of the API, increment for "
                "non-backwards compatible changes",
                method_options={
                    # This special path applies to all resource paths
                    # and all HTTP methods
                    "/*/*":
                        api_gw.MethodDeploymentOptions(
                            # TODO: Configure caching for improved performance.
                            # May also need to decrease the logging when we
                            # have traffic.
                            data_trace_enabled=True,
                            logging_level=api_gw.MethodLoggingLevel("INFO"),
                            # Setup some basic throttling.
                            # These numbers are pretty arbitrary, update later.
                            throttling_rate_limit=100,
                            throttling_burst_limit=200)
                },
                # Should match custom domain base path mapping.
                stage_name=API_BASE_NAME,
                tracing_enabled=True),
            endpoint_types=[API_ENDPOINT_TYPE],
            fail_on_warnings=True)

        # Attach the API Gateway to a custom domain.
        # Keep the stage name and base path the same, tied to the major
        # version number of the API, so we can version the API via the URL,
        # e.g. https://api.app.videoncloud.com/v1/whatever points to version
        # 1.x of the API.  In the future, we may have multiple stages and
        # versions of the API deployed.
        custom_domain = api_gw.DomainName(  # pylint: disable=unexpected-keyword-arg
            self,
            "CustomDomain",
            certificate=acm_cert,
            # In the route53_acm stack, the custom domain name is a
            # mapping lookup which does not transfer cleanly across
            # stacks.  Use Cfn export and import to reference the value
            # instead.
            domain_name=f"{API_HOST_NAME}."
            f"{core.Fn.import_value(route53_zone_name_export)}",
            endpoint_type=API_ENDPOINT_TYPE,
            # pylint chokes on this line and I don't know why
            security_policy=api_gw.SecurityPolicy.TLS_1_2)
        custom_domain.add_base_path_mapping(
            self.rest_api,
            # Should match stage name
            base_path=API_BASE_NAME,
            stage=self.rest_api.deployment_stage)

        # Import the zone using the Id and Name so we can create a DNS record.
        route53_zone = route53.PublicHostedZone.from_hosted_zone_attributes(
            self,
            "PublicHostedZone",
            hosted_zone_id=core.Fn.import_value(route53_zone_id_export),
            zone_name=core.Fn.import_value(route53_zone_name_export))

        dns_record = route53.ARecord(
            self,
            "CustomDomainAliasRecord",
            target=route53.RecordTarget.from_alias(
                targets.ApiGatewayDomain(custom_domain)),
            zone=route53_zone,
            record_name=API_HOST_NAME)

        # Since we use a custom domain, we cannot rely on the built-in outputs
        # from SpecRestApi.  Create Cfn Output/Exports of the API gateway URL
        # so we can reference it in other stacks.  Pass the name of the export
        # out of the class so other stacks can import it without breaking CDK
        # dependency ordering.

        api_gateway_fqdn = core.CfnOutput(self,
                                          "ApiGatewayFqdn",
                                          value=dns_record.domain_name,
                                          description="API Gateway FQDN",
                                          export_name="ApiGatewayFqdn")
        self.api_gateway_fqdn_export = api_gateway_fqdn.export_name

        api_gateway_base_path = core.CfnOutput(
            self,
            "ApiGatewayBasePath",
            value=API_BASE_NAME,
            description="API Gateway Base Path",
            export_name="ApiGatewayBasePath")
        self.api_gateway_base_path_export = api_gateway_base_path.export_name

        api_gateway_url = core.CfnOutput(
            self,
            "ApiGatewayUrl",
            value=f"https://{dns_record.domain_name}"
            f"/{API_BASE_NAME}/",
            description="API Gateway URL",
            export_name="ApiGatewayUrl")
        self.api_gateway_url_export = api_gateway_url.export_name

        # Create a Secrets Manager entry that will be used to authenticate
        # INTERNAL communication (e.g. one of our REST APIs calling another).
        # Lambda functions in api_xxxxx stacks will pass in the secret
        # value in the HTTP Authorization header as:
        # VIDEON_INTERNAL_AUTH xxxxxxxxxxxxxxxxx
        # The authorizer function will need this value as well to verify
        # the requests as it processes them.
        videon_internal_auth_secret = secretsmanager.Secret(
            self,
            "VideonInternalAuthSecret",
            description="Auth Token for internal REST API calls",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                exclude_punctuation=True, password_length=32))
        self.videon_internal_auth_arn = \
            videon_internal_auth_secret.secret_full_arn

        # Lambda layers are used to share code and Python packages between
        # functions/stacks.  To share code without creating complex inter-stack
        # dependencies, we will create the same layer in each stack, but
        # reference the same source directory.  Changes to the layer will
        # only be applied to stacks that are re-deployed.
        videon_shared_layer = aws_lambda.LayerVersion(
            self,
            "VideonSharedLayer",
            code=aws_lambda.Code.from_asset("lambda/videon_shared_layer"),
            compatible_runtimes=[aws_lambda.Runtime.PYTHON_3_9],
            description="Videon code shared between Lambda functions/stacks",
            layer_version_name=f"{id}-VideonSharedLayer-v{__version_major__}")

        authorizer_lambda = aws_lambda.Function(
            self,
            "AuthorizerLambda",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="authorizer.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api"),
            description="Authenticates requests to API Gateway",
            # Since this Lambda function is referenced in the OpenAPI
            # definition, we must have a fixed name.  Include version_major
            # in case we need to run multiple versions of the API
            # side-by-side.
            function_name=f"{id}-Authorizer-v{__version_major__}",
            environment={
                "COGNITO_USER_POOL_CLIENT_ID":
                    cognito_user_pool_client.user_pool_client_id,
                "COGNITO_USER_POOL_URL":
                    cognito_user_pool.user_pool_provider_url,
                "COGNITO_USER_POOL_ID":
                    cognito_user_pool.user_pool_id,
                "COGNITO_GLOBAL_ADMINS_GROUP_NAME":
                    cognito_global_admins_group.group_name,
                "COGNITO_GLOBAL_USERS_GROUP_NAME":
                    cognito_global_users_group.group_name,
                "COGNITO_GLOBAL_READERS_GROUP_NAME":
                    cognito_global_readers_group.group_name,
                "COGNITO_DEVICE_MANAGEMENT_GROUP_NAME":
                    cognito_device_management_group.group_name,
                "COGNITO_USER_MANAGEMENT_GROUP_NAME":
                    cognito_user_management_group.group_name,
                "VIDEON_INTERNAL_AUTH_ARN":
                    self.videon_internal_auth_arn,
                "RESTAPI_URL_PATH":
                    self.rest_api.url_for_path("/")
            },
            initial_policy=[
                iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                    actions=[
                                        "secretsmanager:DescribeSecret",
                                        "secretsmanager:GetSecretValue"
                                    ],
                                    resources=[self.videon_internal_auth_arn]),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "cognito-idp:AdminListGroupsForUser",
                    ],
                    resources=[cognito_user_pool.user_pool_arn])
            ],
            layers=[videon_shared_layer],
            log_retention=cw_logs.RetentionDays.THREE_MONTHS,
            timeout=core.Duration.seconds(30),
            tracing=aws_lambda.Tracing.ACTIVE)

        # API Gateway needs permissions to invoke the authorizer
        authorizer_lambda.add_permission(
            "AuthorizerLambdaInvoke",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            # Cannot use arn_for_execute_api() here because it returns the
            # ARN in a format not suitable for authorizers.
            source_arn=f"arn:aws:execute-api:{self.region}:{self.account}:"
            f"{self.rest_api.rest_api_id}/authorizers/*")

        # /test-auth API Route
        # Used by the VideonInternalAuthRotator (it uses this route to test
        # the secret was rotated correctly) and some integration tests.
        test_auth_handler = aws_lambda.Function(
            self,
            "TestAuthHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="test_auth.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api"),
            description="Handler for /test-auth API route",
            # Since this Lambda function is referenced in the OpenAPI
            # definition, we must have a fixed name.  Include version_major
            # in case we need to run multiple versions of the API
            # side-by-side.
            function_name=f"{id}-TestAuthHandler-v{__version_major__}",
            layers=[videon_shared_layer],
            log_retention=cw_logs.RetentionDays.THREE_MONTHS,
            # Lambda Integration in APIGW has a 29 second max timeout.
            timeout=core.Duration.seconds(30),
            tracing=aws_lambda.Tracing.ACTIVE)

        # Grant the API Gateway permission to invoke this Lambda.
        test_auth_handler.add_permission(
            "TestAuthHandlerInvoke",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_arn=f"{self.rest_api.arn_for_execute_api()}")

        # Now that all of the supporting pieces are in place, setup automatic
        # rotation of the secret.  Since this secret is fully automated,
        # rotate it as frequently as possible.  Note that due to reused Lambda
        # containers, we may have some Lambda invocations that keep using old
        # credentials.  We will mitigate this by acceptions AWSCURRENT,
        # AWSPENDING, and AWSPREVIOUS secrets.  But if we rotate too
        # frequently, we may run into a situation where even the AWSPREVIOUS
        # is too new.  If so, slow down the rotation.
        videon_internal_auth_rotator = aws_lambda.Function(
            self,
            "VideonInternalAuthRotator",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="videon_internal_auth_rotator.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api"),
            description="Rotates the Secrets Manager secret "
            f"{videon_internal_auth_secret.secret_name}",
            environment={
                # https://api.app.videoncloud.com/v1/test-auth
                "TEST_SECRET_URL":
                    self.rest_api.deployment_stage.url_for_path("/test-auth")
            },
            initial_policy=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "secretsmanager:DescribeSecret",
                        "secretsmanager:GetSecretValue",
                        "secretsmanager:PutSecretValue",
                        "secretsmanager:UpdateSecretVersionStage"
                    ],
                    resources=[self.videon_internal_auth_arn]),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["secretsmanager:GetRandomPassword"],
                    resources=["*"])
            ],
            layers=[videon_shared_layer],
            log_retention=cw_logs.RetentionDays.THREE_MONTHS,
            timeout=core.Duration.seconds(300))

        # Grant Secrets Manager permission to call the Lambda,
        # and for the Lambda to access the secrets manager (see above).
        # According to the CDK documentation, this SHOULD happen
        # automatically, but it does not.
        # https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets-required-permissions.html
        grant = videon_internal_auth_rotator.grant_invoke(
            iam.ServicePrincipal("secretsmanager.amazonaws.com"))

        # Since this secret is fully automated, rotate it frequently.
        rotation_schedule = videon_internal_auth_secret.add_rotation_schedule(
            "VideonInternalAuthSchedule",
            rotation_lambda=videon_internal_auth_rotator,
            automatically_after=core.Duration.days(1))

        # Ensure the invoke permission is granted before we create the
        # rotation schedule. Otherwise, the CDK deploy may randomly fail here.
        grant.apply_before(rotation_schedule)

        # CATCH-ALL API ROUTE
        # Returns 404 for anything we do not cover explicitly.
        catch_all_handler = aws_lambda.Function(
            self,
            "CatchAllHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="catch_all.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api"),
            description="Catch-All Handler for requests not covered by other "
            "API Gateway integrations",
            # Since this Lambda function is referenced in the OpenAPI
            # definition, we must have a fixed name.  Include version_major
            # in case we need to run multiple versions of the API
            # side-by-side.
            function_name=f"{id}-CatchAllHandler-v{__version_major__}",
            layers=[videon_shared_layer],
            # Lambda Integration in APIGW has a 29 second max timeout.
            timeout=core.Duration.seconds(30),
            log_retention=cw_logs.RetentionDays.THREE_MONTHS,
            tracing=aws_lambda.Tracing.ACTIVE)

        # Grant the API Gateway permission to invoke this Lambda.
        catch_all_handler.add_permission(
            "CatchAllHandlerInvoke",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_arn=f"{self.rest_api.arn_for_execute_api()}")

        # AUTH-INFO API ROUTE
        # Returns the authentication info for a user with the specified email
        # address.  Used by the frontend pre-login to redirect the user to
        # their corresponding identity provider Cognito, Google, Facebook, etc.

        # Handle the case were Cognito wasn't setup with a custom domain.
        # If that's the case, cognito_user_pool_domain.domain_name will only
        # contain the FQDN prefix, and we have to fill in the rest.
        if "." in cognito_user_pool_domain.domain_name:
            cognito_fqdn = cognito_user_pool_domain.domain_name
        else:
            cognito_fqdn = (f"{cognito_user_pool_domain.domain_name}."
                            f"auth.{self.region}.amazoncognito.com")

        auth_info_handler = aws_lambda.Function(
            self,
            "AuthInfoHandler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="auth_info.lambda_handler",
            code=aws_lambda.Code.from_asset("lambda/api"),
            description="Handler for /auth-info route",
            # Since this Lambda function is referenced in the OpenAPI
            # definition, we must have a fixed name.  Include version_major
            # in case we need to run multiple versions of the API
            # side-by-side.
            function_name=f"{id}-AuthInfoHandler-v{__version_major__}",
            environment={
                "COGNITO_REGION":
                    self.region,
                "COGNITO_USER_POOL_CLIENT_ID":
                    cognito_user_pool_client.user_pool_client_id,
                "COGNITO_USER_POOL_DOMAIN":
                    cognito_fqdn,
                "COGNITO_USER_POOL_ID":
                    cognito_user_pool.user_pool_id
            },
            initial_policy=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "cognito-idp:ListUsers",
                        "cognito-idp:GetIdentityProviderByIdentifier"
                    ],
                    resources=[cognito_user_pool.user_pool_arn])
            ],
            layers=[videon_shared_layer],
            # Lambda Integration in APIGW has a 29 second max timeout.
            timeout=core.Duration.seconds(30),
            log_retention=cw_logs.RetentionDays.THREE_MONTHS,
            tracing=aws_lambda.Tracing.ACTIVE)

        # Grant the API Gateway permission to invoke this Lambda.
        auth_info_handler.add_permission(
            "AuthInfoHandlerInvoke",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_arn=f"{self.rest_api.arn_for_execute_api()}")
