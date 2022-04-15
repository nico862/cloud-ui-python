"""Request Handler for /orgs API Route

This is implemented as a Lambda Proxy integration.  The function is
responsible for validating the input, and sending a properly-formatted
response.  (Failure to do so will be a 5xx error for the client.)

https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
https://docs.aws.amazon.com/apigateway/latest/developerguide/handle-errors-in-lambda-integration.html
"""
import boto3
import botocore.exceptions
import json
import logging
import uuid
import requests
import videon_shared as videon

from typing import Union, List

# Enable X-Ray Tracing
from aws_xray_sdk.core import patch_all
from os import environ

patch_all()

dynamodb = boto3.client("dynamodb")
dynamo_paginator_scan = dynamodb.get_paginator("scan")
dynamo_paginator_query = dynamodb.get_paginator("query")

logger = logging.getLogger()

ORGANIZATIONS_TABLE_NAME = environ.get("ORGANIZATIONS_TABLE_NAME")
ORG_USERS_TABLE_NAME = environ.get("ORG_USERS_TABLE_NAME")

COGNITO_ORG_MANAGEMENT_GROUP_NAME = environ.get(
    "COGNITO_ORG_MANAGEMENT_GROUP_NAME")

RESTAPI_URL_PATH = environ.get("RESTAPI_URL_PATH")

secret_manager = boto3.client("secretsmanager")
VIDEON_INTERNAL_AUTH_SECRET: str = secret_manager.get_secret_value(
    SecretId=environ["VIDEON_INTERNAL_AUTH_ARN"])["SecretString"]
VIDEON_INTERNAL_HEADERS = {
    "Authorization": "VIDEON_INTERNAL_AUTH " + VIDEON_INTERNAL_AUTH_SECRET
}


def lambda_handler(event, context):  # pylint: disable=unused-argument

    videon.setup_logging(logging.INFO, event)

    # Basic sanity checks (things that should never happen)
    # If these fail the API Gateway is probably misconfigured
    supported_methods = ("GET", "POST", "OPTIONS")
    assert event["httpMethod"] in supported_methods
    assert "Organization" in event["requestContext"]["operationName"]

    if event["httpMethod"] == "OPTIONS":
        return videon.response_cors(", ".join(supported_methods))

    # Make sure the request body is valid JSON before processing.
    # If it was, the API Gateway should have already validated the
    # parameters.
    if event.get("body") is not None:
        try:
            body = videon.convert_request_body(event["body"])
        except videon.RequestBodyError as err:
            response_json = {"message": str(err)}
            return videon.response_json(400, response_json, event)

    if event["httpMethod"] == "GET":
        return handle_get_orgs(event, context)
    elif event["httpMethod"] == "POST":
        assert "org_name" in body
        response_json = create_organization(body["org_name"])
        # If user isn't VIDEON_INTERNAL_AUTH or isn't 'weird'
        # (aka Authorizer didn't run), make them an admin of the
        # organization they created
        authorizer_user_guid = videon.get_authorizer_guid(event)
        if authorizer_user_guid is not None:
            add_response = requests.post(
                f"{RESTAPI_URL_PATH}orgs/{response_json['org_guid']}/users",
                data=json.dumps({
                    "user_guid": authorizer_user_guid,
                    "access": videon.Permissions.ADMIN
                }),
                headers=VIDEON_INTERNAL_HEADERS)
            if add_response.status_code != 200:
                response_code = add_response.status_code
                message = add_response.json().get("message")
                response_json = {
                    "message": "Organization created successfully, " \
                    "but failed to add user to the organization. Failed " \
                    f"with '{message}'"
                }
                return videon.response_json(response_code, response_json, event)
        response_code = 201

    return videon.response_json(response_code, response_json, event)


def handle_get_orgs(event, context):
    authorizer_user_guid = videon.get_authorizer_guid(event)
    authorizer_user_groups = videon.get_user_groups(event)

    is_org_admin = bool(
        COGNITO_ORG_MANAGEMENT_GROUP_NAME in authorizer_user_groups)

    # Get query string data, and decrypt pagination token if exists
    query_string_params = event.get("queryStringParameters")

    if query_string_params is not None:
        org_name = query_string_params.get("org_name")
        pagination_token = query_string_params.get("pagination_token")
        pagination_size = query_string_params.get("pagination_size")
        target_user_guid = query_string_params.get("user_guid")

        admin_view = bool(is_org_admin and target_user_guid is None)

        if target_user_guid is None:
            target_user_guid = authorizer_user_guid

        if target_user_guid != authorizer_user_guid:
            if not is_org_admin and not videon.is_internal_auth(event):
                response_json = {
                    "message": "User does not have permission to "
                               "perform this action"
                }
                return videon.response_json(403, response_json, event)

        try:
            pagination_size = videon.validate_pagination_size(pagination_size)
        except (TypeError, ValueError) as err:
            response_json = {"message": "Invalid pagination size. " + str(err)}
            return videon.response_json(400, response_json, event)

    else:
        org_name = None
        pagination_token = None
        pagination_size = videon.PAGINATION_SIZE_DEFAULT
        target_user_guid = authorizer_user_guid
        admin_view = is_org_admin

    # user_guid is required for internal auth to pass
    if target_user_guid is None:
        response_json = {"message": "Missing user_guid parameter"}
        return videon.response_json(400, response_json, event)

    # Set up encryption key for pagination token
    pagination_encryption_key = videon.pagination_encryption_key(
        context.function_name, target_user_guid, videon.is_internal_auth(event))

    try:
        pagination_token = videon.pagination_decrypt(pagination_token,
                                                     pagination_encryption_key)

        response_json = find_organizations(target_user_guid, org_name,
                                           pagination_token, pagination_size,
                                           admin_view)

        response_json["pagination_token"] = videon.pagination_encrypt(
            response_json.get("pagination_token"), pagination_encryption_key)

        response_code = 200
    except videon.PaginationTokenError as err:
        response_code = 400
        response_json = {"message": "Invalid pagination token"}

    return videon.response_json(response_code, response_json, event)


def create_organization(org_name):
    org_guid = str(uuid.uuid4())
    org_search_key = videon.get_dynamodb_search_key(org_name)

    logger.info("Creating organization %s, %s, %s", org_guid, org_search_key,
                org_name)

    dynamodb.put_item(TableName=ORGANIZATIONS_TABLE_NAME,
                      Item={
                          "org_guid": {
                              "S": org_guid
                          },
                          "org_search_key": {
                              "S": org_search_key
                          },
                          "org_name": {
                              "S": org_name
                          }
                      })

    return {
        "message": "Organization was created successfully.",
        "org_guid": org_guid
    }


def find_organizations_admin(org_name: str = None,
                             pagination_token=None,
                             pagination_size=videon.PAGINATION_SIZE_DEFAULT):

    pagination_config = {"MaxItems": pagination_size}

    if pagination_token is not None:
        pagination_config["StartingToken"] = pagination_token

    scan_args = {
        "TableName": ORGANIZATIONS_TABLE_NAME,
        "IndexName": "org_search_key",
        "Select": "SPECIFIC_ATTRIBUTES",
        "ProjectionExpression": "org_name,org_guid",
        "PaginationConfig": pagination_config
    }
    if org_name is not None:
        # Due to variations in capitalization, spacing, punctuation, etc.
        # we do not search for the org name directly.  To provide a better
        # user experience, we store a "search key" and match on any subset of
        # that string.
        org_search_key = videon.get_dynamodb_search_key(org_name)
        filter_expression = "contains(org_search_key, :search_value)"
        filter_expression_values = {":search_value": {"S": org_search_key}}
        logger.info("Find organization with a search key matching %s",
                    org_search_key)

        scan_args["FilterExpression"] = filter_expression
        scan_args["ExpressionAttributeValues"] = filter_expression_values
    else:
        # If they did not pass in an org name, just search for everything.
        logger.info("org_name not specified, finding all organizations")

    try:
        response = dynamo_paginator_scan.paginate(
            **scan_args).build_full_result()
    except botocore.exceptions.ParamValidationError as err:
        if "ExclusiveStartKey" in str(err):
            raise videon.PaginationTokenError from err
        raise botocore.exceptions.ParamValidationError from err

    logger.info("DynamoDB response: %s", json.dumps(response))

    # The scan() response formatting is quite different than we want it
    # to look in the output to our API client.  Make a new dict and transfer
    # over the properties we need in the format we want.
    output = dict()
    output["orgs"] = list()
    for item in response["Items"]:
        item_name = item["org_name"]["S"]
        item_guid = item["org_guid"]["S"]
        output["orgs"].append({"org_name": item_name, "org_guid": item_guid})

    output["pagination_token"] = response.get("NextToken")

    return output


def find_organizations(user_guid,
                       org_name=None,
                       pagination_token=None,
                       pagination_size=videon.PAGINATION_SIZE_DEFAULT,
                       admin_view=False):
    if admin_view:
        return find_organizations_admin(org_name, pagination_token,
                                        pagination_size)

    organization_memberships: List[str] = list()
    member_pagination: Union[str, None] = None
    while True:
        response = get_orgs_by_user(user_guid, member_pagination)
        user_orgs = response["orgs"]
        organization_memberships.extend(user_orgs)

        member_pagination = response.get("pagination_token")
        if member_pagination is None:
            break

    logger.info(pagination_token)
    start_ind: int = 0 if pagination_token is None \
        else json.loads(pagination_token)["start"]

    found_orgs = []
    found_orgs_count = 0
    for organization in organization_memberships[start_ind:]:
        guid = organization["org_guid"]
        response = dynamodb.get_item(TableName=ORGANIZATIONS_TABLE_NAME,
                                     Key={"org_guid": {
                                         "S": guid
                                     }},
                                     ConsistentRead=True)
        item = response.get("Item")
        if not item:
            logger.info("Ghost Organization: %s", guid)
            found_orgs_count += 1
            if found_orgs_count >= pagination_size:
                break
            continue

        response_org_name = item["org_name"]["S"]

        if org_name is None or org_name in response_org_name:
            found_orgs.append({
                "org_name": response_org_name,
                "org_guid": guid,
                "access": organization["access"]
            })
            found_orgs_count += 1
            if found_orgs_count >= pagination_size:
                break

    next_ind = found_orgs_count + start_ind
    pagination_token = None if len(organization_memberships[next_ind:]) == 0 \
        else json.dumps({ "start": next_ind })

    return {"orgs": found_orgs, "pagination_token": pagination_token}


def get_orgs_by_user(user_guid, pagination_token):
    pagination_config: dict = {"MaxItems": 100}
    if pagination_token is not None:
        pagination_config["StartingToken"] = pagination_token

    expression_values = {":user_guid": {"S": user_guid}}

    try:
        response = dynamo_paginator_query.paginate(
            TableName=ORG_USERS_TABLE_NAME,
            IndexName="user_guid",
            Select="SPECIFIC_ATTRIBUTES",
            ProjectionExpression="org_guid,access",
            KeyConditionExpression="user_guid = :user_guid",
            ExpressionAttributeValues=expression_values,
            PaginationConfig=pagination_config).build_full_result()
    except botocore.exceptions.ParamValidationError as err:
        if "ExclusiveStartKey" in str(err):
            raise videon.PaginationTokenError from err
        raise err

    logger.info("DynamoDB response: %s", json.dumps(response))

    output = {"orgs": []}
    for item in response["Items"]:
        org_guid: str = item["org_guid"]["S"]
        access: int = int(item["access"]["N"])

        output["orgs"].append({"org_guid": org_guid, "access": access})
    output["pagination_token"] = response.get("NextToken")

    return output
