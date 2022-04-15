"""CDK Stack - Route53 and ACM

This stack creates a Route 53 Public DNS zone and wildcard ACM certificate
for the domain.

The DNS Zone for each deployed instance of the cloud platform should be a
subdomain of videoncloud.com, e.g. app.videoncloud.com.  The parent DNS zone
(videoncloud.com) is managed in the videon-corp-01 AWS account and delegates
permissions to accounts that can create subdomains in that zone.

THE VIDEON-CORP-01 ACCOUNT DEPLOYMENT NEEDS TO KNOW THE AWS ACCOUNT NUMBER
OF THIS DEPLOYMENT BEFORE YOU ATTEMPT TO DEPLOY THIS CDK STACK.  YOU MUST
LIST THE ACCOUNT NUMBER UNDER cross_account_zone_delegation_principal.
"""

from aws_cdk import (aws_certificatemanager as acm, aws_iam as iam, aws_route53
                     as route53, core)

# The AWS account number and IAM role from the videon-corp-01 account.
# See the Route53VideonCloudCom CDK Stack in the aws-infrastructure repo.
# If this is a new deployment, make sure you add the AWS account number
# for THIS deployment to cross_account_zone_delegation_principal in
# videon-corp-01.
PARENT_DNS_ZONE_ACCOUNT_NUM = "296025497120"
PARENT_DNS_ZONE_IAM_ROLE = "Route53VideonCloudCom"
PARENT_DNS_ZONE_NAME = "videoncloud.com"

# Mapping of AWS account number to domain name.
# Domains should all be a subdomain of videoncloud.com.
# As we add deployments, be sure add them to the list.
# Note the account number should also be added to the
# cross_account_zone_delegation_principal in videon-corp-01.
account_to_domain_name = {
    "458280733286": "dev01.videoncloud.com",  # videon-dev-01
}


class Route53AcmStack(core.Stack):
    """CDK Stack Class

    This stack is free-standing and does not have any dependencies, but
    several other stacks will depend on it.
    """

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Because we will not know the AWS account number until deployment,
        # put the Python mapping into a CloudFormation Mapping.  Cfn maps
        # enforce a two-level hierarchy, so the first level is a single
        # element called "accounts".
        # To ensure the domain name is properly tokenized processed, avoid
        # referenceing this mapping and instead use self.dns.zone_name.
        zone_names = core.CfnMapping(
            self,
            "ZoneNameMapping",
            mapping={"accounts": account_to_domain_name})

        dns_zone = route53.PublicHostedZone(
            self,
            "DnsZone",
            zone_name=zone_names.find_in_map("accounts", core.Aws.ACCOUNT_ID),
            comment=f"CDK stack {id}, "
            f"delegated from {PARENT_DNS_ZONE_ACCOUNT_NUM}")

        # Because the DNS zone name is a mapping lookup, the object does not
        # transfer cleanly between CDK stacks.  Instead, we will export the
        # zone name and ID so that other stacks may import them.  Other stacks
        # can reference these values with core.Fn.import_value(export_name).
        # To ensure dependency ordering is respected, be sure to have the
        # dependent stack reference the exported names listed below.
        dns_zone_name = core.CfnOutput(
            self,
            "DnsZoneName",
            value=dns_zone.zone_name,
            description="Route53 Public DNS Zone Name",
            export_name="Route53AcmDnsZoneName")
        self.zone_name_export = dns_zone_name.export_name

        dns_zone_id = core.CfnOutput(self,
                                     "DnsZoneId",
                                     value=dns_zone.hosted_zone_id,
                                     description="Route53 Public DNS Zone Id",
                                     export_name="Route53AcmDnsZoneId")
        self.zone_id_export = dns_zone_id.export_name

        # When we create the DNS zone for the subdomain in this account, we
        # must create/update corresponding NS records in the parent zone,
        # which lives in the videon-corp-01 account.
        #
        # The account with the parent DNS zone has a pre-created IAM role that
        # we can assume to manage those NS records.  Construct the ARN of the
        # role so we can assume it.
        delegation_role_arn = core.Stack.of(self).format_arn(
            region="",  # IAM is global in each partition
            service="iam",
            account=PARENT_DNS_ZONE_ACCOUNT_NUM,
            resource="role",
            resource_name=PARENT_DNS_ZONE_IAM_ROLE)
        delegation_role = iam.Role.from_role_arn(self, "DelegationRole",
                                                 delegation_role_arn)

        route53.CrossAccountZoneDelegationRecord(
            self,
            "DelegationRecord",
            delegated_zone=dns_zone,
            parent_hosted_zone_name=PARENT_DNS_ZONE_NAME,
            delegation_role=delegation_role,
            ttl=core.Duration.days(1))

        self.certificate = acm.Certificate(
            self,
            "Certificate",
            domain_name=f"*.{dns_zone.zone_name}",
            subject_alternative_names=[dns_zone.zone_name],
            # We have to use multi-zone validation even though we are only
            # validating one zone.  Otherwise, the validation tries to make
            # duplicate DNS entries in the zone for *.app.videoncloud.com
            # and app.videoncloud.com, which causes an error.
            validation=acm.CertificateValidation.from_dns_multi_zone(
                {dns_zone.zone_name: dns_zone}))

        # Most "global" AWS services like CloudFront can only support ACM
        # certificates in us-east-1.  This also applies to services that use
        # CloudFront behind the scenes like Cognito.
        # If we are using another region, create a cert in us-east-1 as well
        # so we can create CloudFront distributions without too much trouble.

        not_us_east_1 = core.CfnCondition(self,
                                          "NotUsEast1Condition",
                                          expression=core.Fn.condition_not(
                                              core.Fn.condition_equals(
                                                  self.region, "us-east-1")))

        self.certificate_us_east_1 = acm.DnsValidatedCertificate(
            self,
            "CertificateUsEast1",
            hosted_zone=dns_zone,
            region="us-east-1",
            domain_name=f"*.{dns_zone.zone_name}",
            subject_alternative_names=[dns_zone.zone_name],
            # Do not need to create validation DNS entries again.
            validation=acm.CertificateValidation.from_dns())

        self.certificate_us_east_1.node.children[
            0].node.default_child.cfn_options.condition = not_us_east_1
