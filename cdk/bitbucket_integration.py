"""CDK Stack - Bitbucket Integration

This stack creates the resources needed for Bitbucket Pipelines to talk to this
AWS account for CI/CD.  You will need this in any account where deployments are
automated through Bitbucket cloud.
"""

from aws_cdk import (aws_iam as iam, core)
import re


class BitbucketIntegrationStack(core.Stack):
    """CDK Stack Class

    This stack is free-standing and does not have any dependencies or
    dependents.
    """

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # We currently use Bitbucket pipelines as our CI/CD system to follow
        # the ways of DevOps.  To allow the Bitbucket pipeline to access the
        # AWS account, we use OpenID Connect, which is safer than long-lived
        # IAM credentials like an Access Key.  You must register Bitbucker as
        # an OIDC provider in the AWS account before the pipeline will work.
        # If you are bootstrapping a new AWS account, you will have to run a
        # 'cdk deploy' manually to create the resources.
        # https://support.atlassian.com/bitbucket-cloud/docs/integrate-pipelines-with-resource-servers-using-oidc/
        # https://support.atlassian.com/bitbucket-cloud/docs/deploy-on-aws-using-bitbucket-pipelines-openid-connect/

        # These values came from
        # https://bitbucket.org/videonlabs/aws-cloud-platform/admin/addon/admin/pipelines/openid-connect
        # They are specific to our Bitbucket workspace/repository.
        bitbucket_oidc_idp_url = \
            "https://api.bitbucket.org/2.0/workspaces/videonlabs" \
            "/pipelines-config/identity/oidc"
        bitbucket_oidc_audience = \
            "ari:cloud:bitbucket::workspace" \
            "/362877c6-701c-46ba-9036-4f2dabfba2a7"

        # aws-cloud-platform repo
        bitbucket_oidc_repo_uuid1 = "{0e58fd46-ea94-414b-8e00-022214d2053a}"

        # cloud-ui-poc repo
        bitbucket_oidc_repo_uuid2 = "{8cacae21-9ce9-4339-a260-d08ef5a6aea5}"

        # cloud-ui repo
        bitbucket_oidc_repo_uuid3 = "{d7c26b99-7d93-4d97-be32-40e979c9402c}"

        bitbucket_provider = iam.OpenIdConnectProvider(
            self,
            "bitbucketProvider",
            url=bitbucket_oidc_idp_url,
            client_ids=[bitbucket_oidc_audience])

        # Add a condition to the principal so it will only work from this
        # repository.  Without this condition, any pipeline in our workspace
        # would be able to assume the IAM role.
        # https://support.atlassian.com/bitbucket-cloud/docs/deploy-on-aws-using-bitbucket-pipelines-openid-connect/

        bitbucket_provider_name = re.sub("^https://", "",
                                         bitbucket_oidc_idp_url)
        bitbucket_principal = iam.OpenIdConnectPrincipal(
            open_id_connect_provider=bitbucket_provider,
            conditions={
                "StringLike": {
                    f"{bitbucket_provider_name}:sub": [
                        f"{bitbucket_oidc_repo_uuid1}:*",
                        f"{bitbucket_oidc_repo_uuid2}:*",
                        f"{bitbucket_oidc_repo_uuid3}:*"
                    ]
                }
            })

        # IAM role that will be used by the Bitbucket pipeline when it
        # connects to the AWS account.  Instead of using the auto-generated
        # role name, set it to a specific well-known name that we can
        # reference in the pipeline scripts.
        iam.Role(
            self,
            "bitbucketRole",
            assumed_by=bitbucket_principal,
            description="Used by Bitbucket pipelines for automated deployment",
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AdministratorAccess")
            ],
            role_name="bitbucket-pipelines")
