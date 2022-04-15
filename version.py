"""Define the version number of this project in a single canonical location.

This should be the ONLY place where a version number is defined anywhere in
the project.

We follow Semantic versioning X.Y.Z.
  X = Major version, increment when there are breaking non-backwards
      compatible changes (e.g. an API was removed/renamed).
  Y = Minor version, increment for new features (e.g. added a new API).
  Z = Patch version, increment for non-structural changes (e.g. bugfixes).
X and Y will be set explicitly, and must be updated manually.
Z will be auto-generated by our build pipeline.
If this project is deployed outside of the pipeline, the local timestamp will
be used as a substitute.
"""

__version_major__ = "1"
__version_minor__ = "0"

# Bitbucket puts the build number in the pipeline as BITBUCKET_BUILD_NUMBER.
# https://support.atlassian.com/bitbucket-cloud/docs/variables-and-secrets/
from os import environ
from datetime import datetime, timezone
if environ.get("BITBUCKET_BUILD_NUMBER") is not None:
    __version_patch__ = environ.get("BITBUCKET_BUILD_NUMBER")
else:
    # Someone is building locally
    # This is not an ideal build number, but it will be unique, incrementing,
    # and easy to distinguish from an official build.
    # Use the UTC so it is consistent across time zones.
    __version_patch__ = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    # If we know the current username, append it to the version,
    # helps us identify who deployed it.
    # On Windows this is in the environment variable USERNAME,
    # Linux/Mac use USER
    if environ.get("USERNAME") is not None:
        __version_patch__ = f"{__version_patch__}-{environ.get('USERNAME')}"
    elif environ.get("USER") is not None:
        __version_patch__ = f"{__version_patch__}-{environ.get('USER')}"

__version__ = f"{__version_major__}.{__version_minor__}.{__version_patch__}"

# Other files in this project can include version.py and reference __version__
# or its friends major/minor/patch.
#
# Ways you can include version.py:
#
#   In project code:
#       from .version import __version__
#
#   If the package is not loaded yet:
#       __version__="See version.py"
#       exec(open("./version.py").read()) # pylint: disable=exec-used
#   Set a placeholder value of __version__ to suppress warnings about
#   referencing an undefined variable.
#   Also shut off pylint warnings about the use of exec().