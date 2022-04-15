"""CDK Stack - SES

This stack creates templates for sending emails to users.
"""

from aws_cdk import (aws_ses as ses, core)

# Read the project version number from canonical source in version.py
# Available as __version__.
# Set a placeholder value to stop warnings about undefined variables.
__version__ = "See version.py"
__version_major__ = "See version.py"
exec(open("./version.py").read())  # pylint: disable=exec-used

class SESStack(core.Stack):
    """CDK Stack Class

    Requires the following parameters:
        route53_zone_name_export: Cfn Export name for Zone Name
    """

    def __init__(self, scope: core.Construct, id: str,
                 route53_zone_name_export, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        self.from_email_noreply = "noreply@videoncloud.com"
        site_url = core.Fn.import_value(route53_zone_name_export)

        self.invite_template_name = f"{id}-InviteTemplate-v{__version_major__}"
        invite_subject = "Videon Cloud Platform Organization Invitation"
        invite_html = ("<p>You have been invited to join an organization on "
               "the Videon Cloud Platform! Please sign in or create "
               f"an account at {site_url} to respond to the invite.</p>")
        invite_text = ("You have been invited to join an organization on the "
               "Videon Cloud Platform! Please sign in or create an "
               f"account at {site_url} to respond to the invite.")

        ses.CfnTemplate(self, "SESInviteTemplate",
            template=ses.CfnTemplate.TemplateProperty(
                html_part=invite_html,
                subject_part=invite_subject,
                template_name=self.invite_template_name,
                text_part=invite_text
            )
        )
