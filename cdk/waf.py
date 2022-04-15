"""CDK Stack - Web Application Firewall CDK Stack

This stack implements a Web Application Firewall to protect our public-facing
resources (API Gateways, Load Balancers) against common HTTP-based attacks,
BEFORE it reaches our application.

Currently we only worry about the API Gateway, but we implemented this as a
freestanding CDK stack so that we can use the same WAF instance to protect
other resource in the future.  WAFs a priced per ACL+rule per month, so if
we can use the same WAF to protect multiple resources, it reduces costs.
"""

from aws_cdk import (aws_wafv2 as waf, core)


class WafStack(core.Stack):
    """CDK Stack Class

    Attributes:
        apigw_restapi: API gateway object to protect (from ApiStack)

    In the future we will have other inputs to this stack.
    """

    def __init__(self, scope: core.Construct, id: str, apigw_restapi,
                 **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        waf_rules = []

        # AWS Managed Rules
        # https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html

        # 1, Internal Auth Allow
        aws_managed_rules = waf.CfnWebACL.RuleProperty(
            name="InternalAuthenticationRule",
            priority=1,
            action=waf.CfnWebACL.RuleActionProperty(allow={}),
            statement=waf.CfnWebACL.StatementProperty(
                byte_match_statement=waf.CfnWebACL.ByteMatchStatementProperty(
                    field_to_match=waf.CfnWebACL.FieldToMatchProperty(
                        single_header={"Name": "Authorization"}),
                    positional_constraint="STARTS_WITH",
                    text_transformations=[
                        waf.CfnWebACL.TextTransformationProperty(priority=1,
                                                                 type="NONE")
                    ],
                    search_string="VIDEON_INTERNAL_AUTH",
                )),
            visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="InternalAuthenticationRule",
                sampled_requests_enabled=True,
            ),
        )
        waf_rules.append(aws_managed_rules)

        # 2, Core rule set (CRS)
        aws_managed_rules = waf.CfnWebACL.RuleProperty(
            name="AWSManagedRulesCommonRuleSet",
            priority=2,
            override_action=waf.CfnWebACL.OverrideActionProperty(none={}),
            statement=waf.CfnWebACL.StatementProperty(
                managed_rule_group_statement=waf.CfnWebACL.
                ManagedRuleGroupStatementProperty(
                    name="AWSManagedRulesCommonRuleSet",
                    vendor_name="AWS",
                    excluded_rules=[
                        waf.CfnWebACL.ExcludedRuleProperty(
                            name="SizeRestrictions_BODY")
                    ])),
            visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="AWSManagedRulesCommonRuleSet",
                sampled_requests_enabled=True,
            ),
        )
        waf_rules.append(aws_managed_rules)

        # 3, Anonymous IP list
        aws_anoniplist = waf.CfnWebACL.RuleProperty(
            name="AWSManagedRulesAnonymousIpList",
            priority=3,
            override_action=waf.CfnWebACL.OverrideActionProperty(none={}),
            statement=waf.CfnWebACL.StatementProperty(
                managed_rule_group_statement=waf.CfnWebACL.
                ManagedRuleGroupStatementProperty(
                    name="AWSManagedRulesAnonymousIpList",
                    vendor_name="AWS",
                    # By default, Anonymous IPs also include cloud hosting
                    # providers, INCLUDING AWS.  This can break internal
                    # traffic from our REST API to itself.
                    excluded_rules=[
                        waf.CfnWebACL.ExcludedRuleProperty(
                            name="HostingProviderIPList")
                    ])),
            visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="AWSManagedRulesAnonymousIpList",
                sampled_requests_enabled=True,
            ))
        waf_rules.append(aws_anoniplist)

        # 4 Amazon IP reputation list
        aws_ip_rep_list = waf.CfnWebACL.RuleProperty(
            name="AWSManagedRulesAmazonIpReputationList",
            priority=4,
            override_action=waf.CfnWebACL.OverrideActionProperty(none={}),
            statement=waf.CfnWebACL.StatementProperty(
                managed_rule_group_statement=waf.CfnWebACL.
                ManagedRuleGroupStatementProperty(
                    name="AWSManagedRulesAmazonIpReputationList",
                    vendor_name="AWS",
                    excluded_rules=[])),
            visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="AWSManagedRulesAmazonIpReputationList",
                sampled_requests_enabled=True,
            ))
        waf_rules.append(aws_ip_rep_list)

        # 5 GeoBlock countries that are common sources of bot traffic, and
        # have no legit reason to be accessing our API.
        geoblock_rule = waf.CfnWebACL.RuleProperty(
            name="Geoblocking",
            priority=5,
            action=waf.CfnWebACL.RuleActionProperty(block={}),
            statement=waf.CfnWebACL.StatementProperty(
                geo_match_statement=waf.CfnWebACL.GeoMatchStatementProperty(
                    country_codes=["RU", "CN"],)),
            visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="Geoblocking",
                sampled_requests_enabled=True,
            ))
        waf_rules.append(geoblock_rule)

        # Create the WAF ACL
        # Use a descriptive name so we can associate it back to the API
        # Gateway.  Don't use API GW name here because periods are not allowed
        # in WAF ACL name.
        waf_name = f"apigw-{apigw_restapi.rest_api_id}-" \
                   f"{apigw_restapi.deployment_stage.stage_name}"
        web_acl = waf.CfnWebACL(
            self,
            "WebAcl",
            default_action=waf.CfnWebACL.DefaultActionProperty(allow={}),
            scope="REGIONAL",  # vs "CLOUDFRONT"
            visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name=waf_name,
                sampled_requests_enabled=True),
            description=f"Protects {apigw_restapi.rest_api_name} "
            "API Gateway stage "
            f"{apigw_restapi.deployment_stage.stage_name}",
            name=waf_name,
            rules=waf_rules)

        # Associate it with the resource provided.
        resource_arn = f"arn:aws:apigateway:{core.Stack.of(self).region}::" \
                       f"/restapis/{apigw_restapi.rest_api_id}/stages" \
                       f"/{apigw_restapi.deployment_stage.stage_name}"
        waf.CfnWebACLAssociation(self,
                                 "WebAclAssociationApi",
                                 web_acl_arn=web_acl.attr_arn,
                                 resource_arn=resource_arn)
