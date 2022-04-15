"""CDK Stack - Cognito

This stack implements a Cognito User Pool and other supporting resources.

Cognito provides our user authentication service.  The web application will
authenticate users interactively.  The REST API will be expecting a JWT token
from Cognito.
"""

from aws_cdk import (aws_cognito as cognito, aws_route53 as route53,
                     aws_route53_targets as targets, core)


class CognitoStack(core.Stack):
    """CDK Stack Class

    Attributes:
        acm_cert_us_east_1: ACM Certificate Object from Route53AcmStack
                            (NOTE: MUST BE A CERT IN US-EAST-1)
        route53_zone_id_export: Cfn Export name for Zone Id (Route53AcmStack)
        route53_zone_name_export: Cfn Export name for Zone Name
    """

    def __init__(self, scope: core.Construct, id: str, acm_cert_us_east_1,
                 route53_zone_id_export, route53_zone_name_export,
                 **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        self.user_pool = cognito.UserPool(
            self,
            "VideonUserPool",
            account_recovery=cognito.AccountRecovery.EMAIL_ONLY,
            auto_verify=cognito.AutoVerifiedAttrs(email=True, phone=False),
            # TODO: uncomment this when we have a working custom domain
            # for sending email (SES).
            # https://github.com/aws/aws-cdk/issues/6768
            # email_settings={
            #     "from_": "support@videoncloud.com",
            #     "reply_to": "support@videoncloud.com"
            # },
            mfa=cognito.Mfa.OPTIONAL,
            mfa_second_factor={
                "sms": True,
                "otp": True
            },
            password_policy={
                "min_length":
                    8,
                "require_lowercase":
                    True,
                "require_uppercase":
                    True,
                "require_digits":
                    True,
                "require_symbols":
                    False,
                "temp_password_validity":
                    core.Duration.days(1)  # Must be a whole number of days
            },
            self_sign_up_enabled=True,
            sign_in_aliases=cognito.SignInAliases(email=True,
                                                  phone=False,
                                                  preferred_username=False,
                                                  username=False),
            sign_in_case_sensitive=False,
            # CHANGES HERE MAY REQUIRE A DESTROY/REPLACE OF THE USER POOL,
            # WHICH WILL DELETE ALL OF THE USERS.  MAKE SURE THIS LIST IS
            # GOOD BEFORE MOVING INTO PRODUCTION.
            standard_attributes=cognito.StandardAttributes(
                email=cognito.StandardAttribute(mutable=True, required=True),
                fullname=cognito.StandardAttribute(mutable=True, required=True),
                locale=cognito.StandardAttribute(mutable=True, required=False),
                phone_number=cognito.StandardAttribute(mutable=True,
                                                       required=False),
                profile_picture=cognito.StandardAttribute(mutable=True,
                                                          required=False),
                timezone=cognito.StandardAttribute(mutable=True,
                                                   required=False)),
            user_invitation={
                "email_body":
                    "You have been invited to the Videon Cloud Platform! "
                    "Please sign in with your email address {username} and "
                    "temporary password {####}.",
                "email_subject": "Videon Cloud Platform Invitation",
                # Users should never see this one.
                "sms_message": "SMS SIGN-IN DISABLED {username} {####}"
            },
            user_verification={
                "email_body":
                    "Welcome to the Videon Cloud Platform! Please click the "
                    "link to verify your email address."
                    "\r\n\r\n{##Verify Email##}",
                "email_style": cognito.VerificationEmailStyle.LINK,
                "email_subject":
                    "ACTION REQUIRED: Verify your email for the Videon Cloud "
                    "Platform"
            })

        self.user_pool_client = cognito.UserPoolClient(
            self,
            "VideonCloudPlatformClient",
            user_pool=self.user_pool,
            access_token_validity=core.Duration.minutes(60),
            auth_flows={
                # https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow.html
                "admin_user_password": True,
                "custom": True,
                "user_password": True,
                "user_srp": True
            },
            disable_o_auth=False,
            generate_secret=False,
            id_token_validity=core.Duration.minutes(60),
            o_auth={
                # TODO: Replace this with the proper domain of the web app
                # Localhost should only be allowed for non-prod environments.
                "callback_urls": ["https://localhost"],
                "flows": {
                    # See Allowed OAuth Flows for an explanation of what these
                    # values mean:
                    # https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-app-idp-settings.html
                    "authorization_code_grant": True,
                    "client_credentials": False,
                    "implicit_code_grant": True
                },
                "logout_urls": ["https://videonlabs.com"],
                "scopes": [
                    # See Allowed OAuth Scopes for an explanation of what these
                    # values mean:
                    # https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-app-idp-settings.html
                    # For a high-level overview of OAuth scopes:
                    # https://oauth.net/2/scope/
                    cognito.OAuthScope.PHONE,
                    cognito.OAuthScope.EMAIL,
                    cognito.OAuthScope.OPENID,
                    cognito.OAuthScope.PROFILE,
                    cognito.OAuthScope.COGNITO_ADMIN
                ]
            },
            # Mask whether or not users exist from clients signing in,
            # prevents information disclosure that may enable phishing.
            prevent_user_existence_errors=True,
            read_attributes=cognito.ClientAttributes().with_standard_attributes(
                email=True,
                fullname=True,
                locale=True,
                phone_number=True,
                profile_picture=True,
                timezone=True,
            ),
            # Inactive sessions expire after 24 hours
            refresh_token_validity=core.Duration.days(1),
            write_attributes=cognito.ClientAttributes().
            with_standard_attributes(
                email=True,
                fullname=True,
                locale=True,
                phone_number=True,
                profile_picture=True,
                timezone=True,
            ))

        user_pool_host_name = "auth"
        self.user_pool_domain = cognito.UserPoolDomain(
            self,
            "CognitoDomain",
            user_pool=self.user_pool,
            custom_domain=cognito.CustomDomainOptions(
                certificate=acm_cert_us_east_1,
                domain_name=f"{user_pool_host_name}."
                f"{core.Fn.import_value(route53_zone_name_export)}"))

        # Import the zone using the Id and Name so we can create a DNS record.
        route53_zone = route53.PublicHostedZone.from_hosted_zone_attributes(
            self,
            "PublicHostedZone",
            hosted_zone_id=core.Fn.import_value(route53_zone_id_export),
            zone_name=core.Fn.import_value(route53_zone_name_export))

        route53.ARecord(self,
                        "UserPoolDomainAliasRecord",
                        target=route53.RecordTarget.from_alias(
                            targets.UserPoolDomainTarget(
                                self.user_pool_domain)),
                        zone=route53_zone,
                        record_name=user_pool_host_name)

        # Create Groups in the User pool for special user accounts.
        # We will use these groups to grant "global" permissions to users that
        # are not tied to a specific Organization/Fleet (e.g. Videon customer
        # support employees).
        #
        # Note that groups CANNOT be renamed, they must be replaced.  Any
        # changes to the group names will require you to record the list of
        # members and migrate them to the new group.
        #
        # Unlike most other constructs, we explicitly define the names of these
        # groups to resolve some issue with passing names to other stacks.
        # However, you SHOULD NOT hard-code these names anywhere.  Instead you
        # should get the exported name from this stack and pass it to your
        # code (e.g. an environment variable for a Lambda function).  This will
        # make it more obvious if these groups change and it breaks something.

        self.global_admins_group = cognito.CfnUserPoolGroup(
            self,
            "GlobalAdmins",
            user_pool_id=self.user_pool.user_pool_id,
            description="Members have admin-level permissions in ALL "
            "organizations/fleets (regardless of whether or not "
            "they are assigned to that org/fleet).",
            group_name="GlobalAdmins")

        self.global_users_group = cognito.CfnUserPoolGroup(
            self,
            "GlobalUsers",
            user_pool_id=self.user_pool.user_pool_id,
            description="Members have user-level permissions in ALL "
            "organizations/fleets (regardless of whether or not "
            "they are assigned to that org/fleet).",
            group_name="GlobalUsers")

        self.global_readers_group = cognito.CfnUserPoolGroup(
            self,
            "GlobalReaders",
            user_pool_id=self.user_pool.user_pool_id,
            description="Members have reader-level permissions in ALL "
            "organizations/fleets (regardless of whether or not "
            "they are assigned to that org/fleet).",
            group_name="GlobalReaders")

        self.device_management_group = cognito.CfnUserPoolGroup(
            self,
            "DeviceManagement",
            user_pool_id=self.user_pool.user_pool_id,
            description="Members have API access to create/modify devices "
            "and assign them to organizations, typically used by "
            "service accounts like PDB.",
            group_name="DeviceManagement")

        self.user_management_group = cognito.CfnUserPoolGroup(
            self,
            "UserManagement",
            user_pool_id=self.user_pool.user_pool_id,
            description="Members of this group have the ability to view and "
            "modify the attributes of all user accounts, "
            "regardless of their org/fleet assignment.",
            group_name="UserManagement")

        self.organization_management_group = cognito.CfnUserPoolGroup(
            self,
            "OrganizationManagement",
            user_pool_id=self.user_pool.user_pool_id,
            description="Members of this group have the ability to create "
            "and modify organizations.",
            group_name="OrganizationManagement")
