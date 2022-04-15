"""Python Package Setup File

Created automatically by the CDK when running 'cdk init'.
Use this file to define some top-level project metadata.

Keep the information in this file up-to-date as the project evolves.

https://packaging.python.org/guides/distributing-packages-using-setuptools/
"""

import setuptools

with open("README.md") as fp:
    long_description = fp.read()

# Read the project version number from canonical source in version.py
# Available as __version__.
# Set a placeholder value to stop warnings about undefined variables.
__version__ = "See version.py"
exec(open("./version.py").read())  # pylint: disable=exec-used

setuptools.setup(
    name="aws_cloud_platform",
    version=__version__,
    description="Videon's Cloud Platform provides a simple and intuitive way "
    "for organizations to manage fleets of appliances using an intuitive "
    "website, or an extensive API set.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Videon Labs",
    package_dir={"": "cdk"},
    packages=setuptools.find_packages(where="cdk"),
    install_requires=[
        "aws-cdk.core>=1.145.0",
    ],
    python_requires=">=3.9",
    classifiers=[
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.9",
    ],
)
