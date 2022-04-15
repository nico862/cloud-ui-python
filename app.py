#!/usr/bin/env python3
"""Python Application Root

Root CDK project file for the Videon Cloud Platform, created with 'cdk init'.

To keep the application modular, we we have it broken down into several CDK
stacks, each responsible for one aspect of the application.  This file should
mostly be a list of stack declarations, with most of the heavy lifting done
in the stacks.

For every stack you declare, be sure to specify a description of its purpose
via stack_name.template_options.description

Stack declararations should be listed in order of dependency.
"""

from aws_cdk import core

# In this context, cdk = the cdk subdirectory
from cdk.api import ApiStack
from cdk.api_devices import ApiDevicesStack
from cdk.api_fleets import ApiFleetsStack
from cdk.api_invites import ApiInvitesStack
from cdk.api_openapi import ApiOpenApiStack
from cdk.api_orgs import ApiOrgsStack
from cdk.api_pats import ApiPatsStack
from cdk.api_provisioning import ApiProvisioningStack
from cdk.api_users import ApiUsersStack
from cdk.bitbucket_integration import BitbucketIntegrationStack
from cdk.cognito import CognitoStack
from cdk.frontend import FrontendStack
from cdk.iot_core import IotCoreStack
from cdk.route53_acm import Route53AcmStack
from cdk.ses import SESStack
from cdk.waf import WafStack

app = core.App()

# Without this our Bitbucket pipeline will not work.
bitbucket_integration = BitbucketIntegrationStack(app, "bitbucket-integration")
bitbucket_integration.template_options.description = \
    "Allows Bitbucket CI/CD pipelines to access this AWS account"

# Domain name is determined by AWS account number.
# The mapping of account number -> domain name is internal to the stack.
route53_acm = Route53AcmStack(app, "route53-acm")
route53_acm.template_options.description = \
    "Creates Route53 DNS zone and ACM wildcard certificate"

# Cognito holds our user data
cognito = CognitoStack(app,
                       "cognito",
                       acm_cert_us_east_1=route53_acm.certificate_us_east_1,
                       route53_zone_id_export=route53_acm.zone_id_export,
                       route53_zone_name_export=route53_acm.zone_name_export)
cognito.template_options.description = \
    "Creates Cognito User Pool to be the identity provider for our users"

# SES contains email templates information
ses = SESStack(app,
               "ses",
               route53_zone_name_export=route53_acm.zone_name_export)
ses.template_options.description = \
    "Creates email templates and information to be used when emailing users"

# Create the API gateway from the OpenAPI definition.
api = ApiStack(app,
               "api",
               acm_cert=route53_acm.certificate,
               cognito_user_pool=cognito.user_pool,
               cognito_user_pool_client=cognito.user_pool_client,
               cognito_user_pool_domain=cognito.user_pool_domain,
               cognito_global_admins_group=cognito.global_admins_group,
               cognito_global_users_group=cognito.global_users_group,
               cognito_global_readers_group=cognito.global_readers_group,
               cognito_device_management_group=cognito.device_management_group,
               cognito_user_management_group=cognito.user_management_group,
               openapi_root_file="openapi/api.yml",
               route53_zone_id_export=route53_acm.zone_id_export,
               route53_zone_name_export=route53_acm.zone_name_export)
api.template_options.description = \
    "Videon Cloud Platform REST API (Core Resources)"

# https://api.app.videoncloud.com/v1/openapi
api_openapi = ApiOpenApiStack(app,
                              "api-openapi",
                              apigw_restapi=api.rest_api,
                              apigw_url_export=api.api_gateway_url_export,
                              openapi_obj=api.openapi_obj)
api_openapi.template_options.description = \
    "Videon Cloud Platform REST API (OpenAPI Documentation)"

# https://api.app.videoncloud.com/v1/devices
api_devices = ApiDevicesStack(
    app,
    "api-devices",
    cognito_organization_management_group=cognito.organization_management_group,
    cognito_device_management_group=cognito.device_management_group,
    apigw_restapi=api.rest_api,
    videon_internal_auth_arn=api.videon_internal_auth_arn)
api_devices.template_options.description = \
    "Videon Cloud Platform REST API (Devices)"

# https://api.app.videoncloud.com/v1/fleets
api_fleets = ApiFleetsStack(
    app,
    "api-fleets",
    cognito_organization_management_group=cognito.organization_management_group,
    apigw_restapi=api.rest_api,
    videon_internal_auth_arn=api.videon_internal_auth_arn)
api_fleets.template_options.description = \
    "Videon Cloud Platform REST API (Fleets)"

# https://api.app.videoncloud.com/v1/invites
api_invites = ApiInvitesStack(
    app,
    "api-invites",
    cognito_organization_management_group=cognito.organization_management_group,
    ses_from_email_noreply=ses.from_email_noreply,
    ses_invite_template_name=ses.invite_template_name,
    apigw_restapi=api.rest_api,
    videon_internal_auth_arn=api.videon_internal_auth_arn)
api_invites.template_options.description = \
    "Videon Cloud Platform REST API (Invites)"

# https://api.app.videoncloud.com/v1/orgs
api_orgs = ApiOrgsStack(
    app,
    "api-orgs",
    cognito_organization_management_group=cognito.organization_management_group,
    apigw_restapi=api.rest_api,
    videon_internal_auth_arn=api.videon_internal_auth_arn)
api_orgs.template_options.description = \
    "Videon Cloud Platform REST API (Organizations)"

# https://api.app.videoncloud.com/v1/pats
api_pats = ApiPatsStack(
    app,
    "api-pats",
    apigw_restapi=api.rest_api,
    cognito_user_management_group=cognito.user_management_group,
    videon_internal_auth_arn=api.videon_internal_auth_arn)
api_pats.template_options.description = \
    "Videon Cloud Platform REST API (Personal Access Tokens)"

# https://api.app.videoncloud.com/v1/users
api_users = ApiUsersStack(
    app,
    "api-users",
    apigw_restapi=api.rest_api,
    cognito_user_pool=cognito.user_pool,
    cognito_user_pool_client=cognito.user_pool_client,
    cognito_user_management_group=cognito.user_management_group,
    videon_internal_auth_arn=api.videon_internal_auth_arn)
api_users.template_options.description = \
    "Videon Cloud Platform REST API (Users)"

waf = WafStack(app, "waf", apigw_restapi=api.rest_api)
waf.template_options.description = \
    "Web Application Firewall to protect public-facing resources"

# https://app.videoncloud.com/
frontend = FrontendStack(app,
                         "frontend",
                         acm_cert_us_east_1=route53_acm.certificate_us_east_1,
                         route53_zone_id_export=route53_acm.zone_id_export,
                         route53_zone_name_export=route53_acm.zone_name_export)
frontend.template_options.description = \
    "Frontend UI for Cloud Platform REST API"

# IoT Core is used for device-to-cloud communication.
iot_core = IotCoreStack(app,
                        "iot-core",
                        acm_cert=route53_acm.certificate,
                        device_state_table=api_devices.device_state_table,
                        route53_zone_id_export=route53_acm.zone_id_export,
                        route53_zone_name_export=route53_acm.zone_name_export)
iot_core.template_options.description = \
    "IoT Core for Cloud Platform"

# https://api.app.videoncloud.com/v1/provisioning
api_provisioning = ApiProvisioningStack(
    app,
    "api-provisioning",
    iot_device_policy_name=iot_core.iot_policy_resource_name,
    apigw_restapi=api.rest_api,
    videon_internal_auth_arn=api.videon_internal_auth_arn)
api_provisioning.template_options.description = \
    "Videon Cloud Platform REST API (Provisioning)"

# Capture the output of the synth so we can analyze it in our unit test.
cdk_assembly = app.synth()
