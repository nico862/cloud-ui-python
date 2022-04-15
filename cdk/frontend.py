"""CDK Stack - Frontend Bucket

This stack creates a S3 bucket for storing the compiled frontend app.
"""

from aws_cdk import (aws_cloudfront as cloudfront, aws_cloudfront_origins as
                     origins, aws_route53 as route53, aws_route53_targets as
                     targets, aws_s3 as s3, core)

__version__ = "See version.py"
__version_major__ = "See version.py"
exec(open("./version.py").read())  # pylint: disable=exec-used


class FrontendStack(core.Stack):
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

        # TODO: Fix this name (shouldn't have dev01 in the name).
        # Will have a ripple effect on deployment pipelines.
        bucket = s3.Bucket(self,
                           "videon-dev-01-frontend",
                           removal_policy=core.RemovalPolicy.DESTROY,
                           auto_delete_objects=True)
        distribution = cloudfront.Distribution(
            self,
            "Distribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3Origin(bucket),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.
                REDIRECT_TO_HTTPS),
            certificate=acm_cert_us_east_1,
            error_responses=[
                cloudfront.ErrorResponse(http_status=403,
                                         response_http_status=200,
                                         response_page_path="/")
            ],
            default_root_object="index.html",
            domain_names=[core.Fn.import_value(route53_zone_name_export)])

        route53_zone = route53.PublicHostedZone.from_hosted_zone_attributes(
            self,
            "PublicHostedZone",
            hosted_zone_id=core.Fn.import_value(route53_zone_id_export),
            zone_name=core.Fn.import_value(route53_zone_name_export))

        route53.ARecord(self,
                        "CustomDomainAliasRecord",
                        target=route53.RecordTarget.from_alias(
                            targets.CloudFrontTarget(distribution)),
                        zone=route53_zone)
