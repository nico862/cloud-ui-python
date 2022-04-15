"""Unit Test for CDK

Verify that our CDK code produces the expected stacks.
Do this by running the synth() function and checking the output.

Run tests from the root of the project:
pytest ./tests/unit_test.py

When developing tests, try to follow the given->when->then model.
https://pythontesting.net/strategy/given-when-then-2/
"""

# Import and execute the CDK code so we can validate the output.
# Output should be in cdk_assembly.
# Note this has to be done in the global context.
cdk_assembly = None
exec(open('./app.py').read())  # pylint: disable=exec-used


def test_cdk_app():
    ###########################################################################
    # GIVEN
    ###########################################################################

    ###########################################################################
    # WHEN
    ###########################################################################

    ###########################################################################
    # THEN
    ###########################################################################

    # TODO: Make a test that compares OpenAPI to the Lambda function name.

    # API stack should have created an API Gateway.
    api_stack = cdk_assembly.get_stack_by_name('api')
    assert api_stack is not None
    api_gws = [
        resource for resource in api_stack.template['Resources'].values()
        if resource['Type'] == 'AWS::ApiGateway::RestApi'
    ]
    assert len(api_gws) == 1

    # Bitbucket stack should have created 2 IAM roles.
    bitbucket_stack = cdk_assembly.get_stack_by_name('bitbucket-integration')
    assert bitbucket_stack is not None
    bitbucket_iam_roles = [
        resource for resource in bitbucket_stack.template['Resources'].values()
        if resource['Type'] == 'AWS::IAM::Role'
    ]
    assert len(bitbucket_iam_roles) == 2

    # Cognito stack should have created a user pool.
    cognito_stack = cdk_assembly.get_stack_by_name('cognito')
    assert cognito_stack is not None
    cognito_user_pools = [
        resource for resource in cognito_stack.template['Resources'].values()
        if resource['Type'] == 'AWS::Cognito::UserPool'
    ]
    assert len(cognito_user_pools) == 1

    # TODO: Check the names of these groups so if one of the names changes,
    # the test will fail and we can discuss the impact.
    cognito_groups = [
        resource for resource in cognito_stack.template['Resources'].values()
        if resource['Type'] == 'AWS::Cognito::UserPoolGroup'
    ]
    assert len(cognito_groups) == 6

    # TODO: [CP-42] Come up with more meaningful tests, some ideas:
    #   1. See if we can auto include app.py here instead of copy-paste. (DONE)
    #   2. Make sure all stacks have descriptions populated.
    #   3. Make sure all Lambda functions have descriptions.
    #   4. Unit test the Lambda functions
