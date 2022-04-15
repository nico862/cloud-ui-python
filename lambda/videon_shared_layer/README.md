# Videon Shared Lambda Layer
This directors implements a [layer of shared code/files](https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html) for our AWS Lambda functions.  Due to the modular independent architecture of our platform, you may end up with a lot of duplicate code for things like security, logging, output formatting, etc.  The Lambda layer allows you to share code between our CDK stacks, while still allowing them to be deployed independently.

The contents of this directory will be extracted under /opt of a running Lambda instance.  Any files you place in videon_shared_layer will be available to all Lambda functions in our project (re-deploy required).  However, AWS has a specific directory structure to follow.  **If you make up your own directory names, the Python import statements will fail.**

  * [python](python) - Should contain any Videon-developed functions that can be imported into the Lambda.  Try to keep it all within videon_shared.py, or imported into this file from elsewhere.  This allows for a single import statement in the Lambda function (`import videon_shared as videon`).
  * [python\lib\pythonX.Y\site-packages](python/lib/python3.9/site-packages) - Should contain any external Python packages that our Lambda functions need; either directly or used by videon_shared.

## Managing External Dependencies
External dependencies are typically managed with `pip`.  To ensure that we have repeatable builds and do not introduce security vulnerabilities or other unexpected behavior, all package versions should be listed explicitly in requirements.txt.  Note this is separate from the top-level requirements.txt at the root of the project.

If you need to add a new external package or update an existing one, update requirements.txt accordingly, and then run the following command **from this directory**: `pip install -r ./requirements.txt --target ./python/lib/python3.9/site-packages --upgrade`

After downloading these packages, make sure they are added to our Git repository.

**Important:** Do not run `pip install` from the root of the project.  Make sure you are under videon_shared_layer!
