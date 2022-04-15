"""Videon Shared Lambda Functions

https://operatingops.com/2020/08/30/cloudwatch-json-logs-aws_request_id/
"""

import base64
import datetime
from enum import IntEnum, EnumMeta
import hashlib
import json
import logging
import math
import re
import requests
import urllib.parse

from bleach.sanitizer import Cleaner
from pythonjsonlogger import jsonlogger
from requests.structures import CaseInsensitiveDict

PAGINATION_SIZE_DEFAULT = 50
PAGINATION_SIZE_MAX = 60


class PermissionsEnumMeta(EnumMeta):
    # Allows us to check if an item is in the enum
    # using 'in', e.g. 100 in Permissions
    def __contains__(cls, item):
        return item in cls.__members__.values()


class Permissions(IntEnum, metaclass=PermissionsEnumMeta):
    READER = 100
    USER = 200
    ADMIN = 300


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    """https://operatingops.com/2020/08/30/cloudwatch-json-logs-aws_request_id/
    """

    def __init__(self, *args, **kwargs):
        self.client_ip = kwargs.pop("client_ip", None)
        self.operation_name = kwargs.pop("operation_name", None)
        self.api_request_id = kwargs.pop("api_request_id", None)
        super().__init__(*args, **kwargs)

    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        if self.client_ip is not None:
            log_record["client_ip"] = self.client_ip
        if self.operation_name is not None:
            log_record["operation_name"] = self.operation_name
        if self.api_request_id is not None:
            log_record["api_request_id"] = self.api_request_id


class RequestBodyError(Exception):
    """Returned by convert_request_body()"""
    pass


class PaginationTokenError(Exception):
    """Returned when a pagination token is invalid"""
    pass


class PersonalAccessTokenError(Exception):
    """Returned when a personal access token is invalid"""
    pass


class ResourceNotFoundError(Exception):
    """Returned when a resource cannot be found"""
    pass


class ResourceExistsError(Exception):
    """Returned when a resource already exists"""
    pass


class ResourceConflictError(Exception):
    """Returned when a resource is in a conflicting
    state from what is expected"""
    pass


class UserStatusError(Exception):
    """Returned when a user status is not what is expected"""
    pass


class PermissionsError(Exception):
    """Returned when a user does not have ab appropriate
    permissions level"""
    pass


def convert_request_body(request_body):
    """Converts the request body into a Python dict for further processing.

    Our API expects request bodies in JSON format.  Wherever possible, the
    request body structure, is specified in the OpenAPI definition for each
    path/method as a JSON schema
    (https://json-schema.org/understanding-json-schema/).  This allows the
    request to be validated by the API Gateway before our Lambda handlers are
    ever invoked.  However, if the client passes in an empty, malformed, or
    non-JSON request body, it may slip past the API gateway.  This function
    serves as a sanity check on the request body.

    Any request handler that accepts a request body as an input should call
    this function to convert the body before doing anything with it.  If the
    body is invalid, it will raise an RequestBodyError with an error message
    as the first argument.  If that happens, request handler should immediately
    return a 400 with the error message in the response body, e.g.:

        import videon_shared as videon

        try:
            body = videon.convert_request_body(event["body"])
        except videon.RequestBodyError as err:
            return videon.response_json(400, {"message": str(err)}, event)
    """

    try:
        body_dict = json.loads(request_body)
    except json.JSONDecodeError as err:
        raise RequestBodyError(
            "Request body could not be decoded as valid JSON.") from err
    except TypeError as err:
        raise RequestBodyError("Request body is missing or malformed.") from err

    return body_dict


def get_dynamodb_search_key(value: str):
    """Returns a search key for DynamoDB based on the specified string value.

    DynamoDB has a very rigid query language that make searches difficult.
    It cannot search case-insensitive, and spacing and formatting must be an
    exact match.  To work around this limitation, we will build a collapsed
    "search key" that is easy to search for.

    Use this function to before inserting data into a "search key" attribute
    in a DynamoDB table.  Also call this function before running a query/scan
    on that field.
    """

    # Take a string and turn it into all lowercase, with all non-alphanumeric
    # characters removed.  "Videon Central, Inc." becomes "videoncentralinc"
    search_key = value.lower()
    search_key = re.sub(r"\W", "", search_key)
    search_key = re.sub(r"_", "", search_key)
    return search_key


def get_lowercase_dict(iterable):
    """Converts all keys in a complex dict to lower case.

    Used internally to ensure input structures are in a consistent format.
    Python is case-sensitive, and we hope our users will respect casing in
    their inputs, but if not, I was

    Note: If there are overlapping key names (e.g keyname and KeyName), the
    last one parsed will win.
    """
    renamed = dict()
    if isinstance(iterable, dict):
        for key in iterable.keys():
            renamed[key.lower()] = iterable.get(key)
            if isinstance(iterable[key], (dict, list)):
                renamed[key.lower()] = get_lowercase_dict(iterable[key])
    elif isinstance(iterable, list):
        for item in iterable:
            item = get_lowercase_dict(item)
    return renamed


def response_json(status_code: int, body: dict, event=None):
    """Generates a properly-formatted Lambda response.

    This should be immediately returned by lambda_handler.
    https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html

    status_code: HTTP status code (200, 404, etc.)
    body: Body to be returned in JSON format
    event: The Lambda event object, provides helpful metadata in the response
    """
    # When responding to a credentialed request, the server must specify an
    # origin in the value of the Access-Control-Allow-Origin header, instead
    # of specifying the "*" wildcard.
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
    allow_origin = "*"

    if event is not None and "headers" in event:
        # HTTP headers are case-insensitive, but Python is case-sensitive.
        # This makes it painful to look up headers by name.
        # The requests package has a case-insensitive dict for this purpose.
        headers = CaseInsensitiveDict(event["headers"])
        authorization = headers.get("Authorization", None)
        origin = headers.get("Origin", None)
        if (authorization is not None) and (origin is not None):
            allow_origin = origin

    # If the event input of the Lambda is passed in, we can use it to return
    # some helpful debug info to the user.
    if event is not None and "requestContext" in event:
        operation_name = event["requestContext"].get("operationName", None)
        if operation_name is not None:
            body["operation_name"] = operation_name
        api_request_id = event["requestContext"].get("requestId", None)
        if api_request_id is not None:
            # Use the term api_request_id to distinguish from other types
            # of request Ids.  We are interested in the Id from the gateway,
            # which is traceable through the whole request chain.
            body["api_request_id"] = api_request_id

    body_str = json.dumps(body, default=str)

    # Strip the body of anything HTML so we do not expose ourselves
    # to an XSS vulnerability (e.g. an attacker passes in HTML as an API
    # parameter and we return it in an error message).
    cleaner = Cleaner(tags=[],
                      attributes={},
                      styles=[],
                      protocols=[],
                      strip=True,
                      strip_comments=True,
                      filters=None)
    body_clean = cleaner.clean(body_str)

    logger = logging.getLogger()
    if status_code < 400:
        logger.info("RESPONSE %s: %s", status_code, body_str)
    else:
        logger.error("RESPONSE %s: %s", status_code, body_str)

    return {
        "isBase64Encoded": False,
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": allow_origin
        },
        "body": body_clean
    }


def response_binary(status_code: int,
                    body: dict,
                    event=None,
                    content_type="application/x-tar"):
    """Generates a properly-formatted Lambda response.

    This should be immediately returned by lambda_handler.
    https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html

    status_code: HTTP status code (200, 404, etc.)
    body: Body to be returned in binary format
    event: The Lambda event object, provides helpful metadata in the response
    content_type: the content type to return. Defaults to
    """
    # When responding to a credentialed request, the server must specify an
    # origin in the value of the Access-Control-Allow-Origin header, instead
    # of specifying the "*" wildcard.
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
    allow_origin = "*"

    if event is not None and "headers" in event:
        # HTTP headers are case-insensitive, but Python is case-sensitive.
        # This makes it painful to look up headers by name.
        # The requests package has a case-insensitive dict for this purpose.
        headers = CaseInsensitiveDict(event["headers"])
        authorization = headers.get("Authorization", None)
        origin = headers.get("Origin", None)
        if (authorization is not None) and (origin is not None):
            allow_origin = origin

    return {
        "isBase64Encoded": True,
        "statusCode": status_code,
        "headers": {
            "Content-Type": content_type,
            "Access-Control-Allow-Origin": allow_origin
        },
        "body": base64.b64encode(body).decode("utf-8")
    }


def response_cors(allow_methods="DELETE, GET, PATCH, POST, PUT, OPTIONS",
                  event=None):
    """Generates a properly-formatted Lambda response for CORS preflight.

    This should be immediately returned by lambda_handler, but ONLY in
    response to requests where event["httpMethod"] == "OPTIONS"!

    This function can be called by the Catch All handler to provide a generic
    response to any OPTIONS requests, or each Lambda handler may call it and
    provide their own tailored OPTIONS response.  In the case of the latter,
    pass in a value for allow_methods that matches the supported method(s) for
    that specific API route.

    https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request
    """

    # When responding to a credentialed request, the server must specify an
    # origin in the value of the Access-Control-Allow-Origin header, instead
    # of specifying the "*" wildcard.
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS

    allow_origin = "*"

    if event is not None and "headers" in event:
        # HTTP headers are case-insensitive, but Python is case-sensitive.
        # This makes it painful to look up headers by name.
        # The requests package has a case-insensitive dict for this purpose.
        headers = CaseInsensitiveDict(event["headers"])
        authorization = headers.get("Authorization", None)
        origin = headers.get("Origin", None)
        if (authorization is not None) and (origin is not None):
            allow_origin = origin

    return {
        "isBase64Encoded": False,
        "statusCode": 204,  # No Content
        "headers": {
            "Access-Control-Allow-Credentials":
                True,
            "Access-Control-Allow-Origin":
                allow_origin,
            "Access-Control-Allow-Headers":
                "Content-Type,Authorization,Org-Guid",
            "Access-Control-Allow-Methods":
                allow_methods,
            "Access-Control-Max-Age":
                7200,  # Longest supported by Chrome
            "Content-Type":
                "text/plain"  # Not strictly necessary
        },
        "body": None  # No Content
    }


def setup_logging(log_level, lambda_event=None):
    """Sets up structured JSON logging.

    Call this function as early as possible in lambda_hander(), before you
    generate any output.

    Parameters:
        log_level: logging.INFO, logging.DEBUG, etc.
        lambda_event: Pass in the event parameter from a Lambda function and
                      the logger will extract any request parameters that may
                      be interesting for the log structure.

    https://operatingops.com/2019/09/21/cloudwatch-logs-structured-as-json-with-python-lambda-functions/
    """

    logger = logging.getLogger()

    # Testing showed lambda sets up one default handler. If there are more,
    # something has changed and we want to fail so an engineer can investigate.
    assert len(logger.handlers) == 1

    logger.setLevel(log_level)
    json_handler = logging.StreamHandler()

    fmt_string = "%(asctime)s %(levelname)s %(message)s %(funcName)s %(lineno)d"

    if lambda_event is not None and "headers" in lambda_event:
        # HTTP headers are case-insensitive, but Python is case-sensitive.
        # This makes it painful to look up headers by name.
        # The requests package has a case-insensitive dict for this purpose.
        headers = CaseInsensitiveDict(lambda_event["headers"])
        client_ip = headers.get("X-Forwarded-For", None)
    else:
        client_ip = None

    if lambda_event is not None and "requestContext" in lambda_event:
        operation_name = lambda_event["requestContext"].get(
            "operationName", None)
        api_request_id = lambda_event["requestContext"].get("requestId", None)
    else:
        operation_name = None
        api_request_id = None

    if client_ip is not None:
        fmt_string = fmt_string + " %(client_ip)s"

    if operation_name is not None:
        fmt_string = fmt_string + " %(operation_name)s"

    if api_request_id is not None:
        fmt_string = fmt_string + " %(api_request_id)s"

    formatter = CustomJsonFormatter(fmt=fmt_string,
                                    client_ip=client_ip,
                                    operation_name=operation_name,
                                    api_request_id=api_request_id)

    json_handler.setFormatter(formatter)
    logger.addHandler(json_handler)
    logger.removeHandler(logger.handlers[0])


# Currently, the pagination token returned by boto3 is a base64-encoded
# JSON blob. This (after the 1st MB of data) has the potential of leaking
# organization guid and org_search_key data, which isn't high-severity
# but should still be prevented (NOTE: This problem will stop once
# organization membership is implimented). To remidy this problem we're
# using an XOR cypher, which isn't AES-standard secure, but should be
# enough to prevent people from messing with the pagination token.


def _xor(data: bytes, key: bytes) -> bytearray:
    # If the key is shorter then the data, the result will be truncated
    if len(data) > len(key):
        key *= math.ceil(len(data) / len(key))
    return bytearray(a ^ b for a, b in zip(*map(bytearray, [data, key])))


def pagination_encryption_key(function_name: str,
                              user_guid: str,
                              internal_auth: bool = False) -> str:
    # Performing a hash to decrease the possible attack surface
    # because its possible to get the key if you have an idea of
    # what the plaintext is (one of the problems with XOR). This
    # way, it will be more difficult to figure out the system we
    # use for the key

    h = hashlib.sha256()
    # 'Random' element to make it near-impossible to guess the encryption key
    h.update(b"5d457d3d-ad22-42cf-8e8a-5103931fcae9")

    # Internal auth is not guaranteed to have a user_guid to pass in,
    # so provide one in that case
    if internal_auth and user_guid is None:
        user_guid = "194a9f783-2522-4f78-8b09-f781f3303ade"

    h.update(user_guid.encode())
    h.update(function_name.encode())

    encryption_key = base64.b64encode(h.digest()).decode()

    logger = logging.getLogger()
    logger.info("Generated pagination encryption key: %s", encryption_key)

    return encryption_key


def pagination_encrypt(pagination_token: str, key: str) -> str:
    if pagination_token is None:
        return None

    logger = logging.getLogger()
    logger.info("Plaintext pagination token (ENCRYPTING): %s", pagination_token)

    encrypted_pagination = _xor(pagination_token.encode(), key.encode())
    encrypted_pagination_b64 = urllib.parse.quote(
        base64.b64encode(encrypted_pagination).decode(), safe="")

    logger.info("Encrypted pagination token (ENCRYPTING): %s",
                encrypted_pagination_b64)

    return encrypted_pagination_b64


def pagination_decrypt(pagination_token: str, key: str) -> str:
    if pagination_token is None or pagination_token == "None":
        return None

    logger = logging.getLogger()
    logger.info("Encrypted pagination token (DECRYPTING): %s", pagination_token)

    try:
        unquote_pagination = base64.b64decode(
            urllib.parse.unquote(pagination_token))
    except Exception as err:
        raise PaginationTokenError from err

    try:
        decrypted_pagination_token = _xor(unquote_pagination,
                                          key.encode()).decode()
    except UnicodeDecodeError as err:
        raise PaginationTokenError(unquote_pagination) from err

    logger.info("Plaintext pagination token (DECRYPTING): %s",
                decrypted_pagination_token)

    return decrypted_pagination_token


def get_sha256_hash(token_value):
    """Returns the SHA-256 hash of a given value.

    Use this function to convert plaintext tokens or secrets to their
    stored hash value. NOTE: does not apply to pagination tokens
    """
    h = hashlib.sha256()
    h.update(token_value.encode())
    return h.hexdigest()


# Some tables use a GUID that consists of a membership relationship
# between two resources. This makes it easier to ensure
# no duplicate items are in the table and allows for more efficient
# searches.
# ALWAYS PASS RESOURCES IN THE SAME ORDER, TO GUARANTEE GUID ALWAYS
# GENERATION IS THE SAME
def generate_membership_guid(resource1_guid: str, resource2_guid: str) -> str:
    return f"{resource1_guid},{resource2_guid}"


def is_internal_auth(event):
    """Returns True if the authorizer is VIDEON_INTERNAL_AUTH
    """
    try:
        principal_id = event["requestContext"]["authorizer"]["principalId"]
    except KeyError:
        principal_id = None

    return principal_id == "VIDEON_INTERNAL_AUTH"


def get_authorizer_guid(event):
    """Returns the user guid from the authorizer, if present
    """
    try:
        guid = event["requestContext"]["authorizer"]["UserGUID"]
    except KeyError:
        guid = None

    return guid


def get_user_groups(event):
    """Returns the user groups from the authorizer as a list, if present
    """
    try:
        groups = event["requestContext"]["authorizer"]["UserGroups"]
        groups = json.loads(groups)
    except KeyError:
        groups = []

    return groups


def validate_numeric_param_value(param_value,
                                 min=None,
                                 max=None,
                                 integer=False):
    """Returns a valid numeric parameter value or raises and exception
    if the parameter cannot be converted to a valid one.

    The API Gateway does not validate the type, minimum, or maximum of
    query parameters.

    Use this function to validate the parameter value against given
    restrictions. Parameters of an undesired type will be converted
    to int/float, if possible.

    :param param_value: the value of the parameter from the API
    :param min: the requested minimum for the parameter
    :param max: the requested maximum for the parameter
    :param integer: True when the parameter is of type 'integer',
                    false otherwise
    :return: the valid parameter
    """

    if not isinstance(param_value, int):
        if integer:
            try:
                param_value = int(param_value)
            except ValueError as err:
                raise TypeError("Parameter requires 'integer' type") from err

        elif not isinstance(param_value, float):
            try:
                param_value = float(param_value)
            except ValueError as err:
                raise TypeError("Parameter requires 'number' type") from err

    if min is not None and param_value < min:
        raise ValueError(f"(min: {min}, given: {param_value})")
    if max is not None and param_value > max:
        raise ValueError(f"(max: {max}, given: {param_value})")

    return param_value


def validate_pagination_size(pagination_size):
    """Returns a valid pagination size or raises an exception
    if the size cannot be converted to a valid one.

    The API Gateway does not validate the type, minimum, or maximum of
    query parameters. Many endpoints have a pagination size as part
    of their query parameters.

    Use this function to validate the pagination size.
    """
    if pagination_size is None:
        pagination_size = PAGINATION_SIZE_DEFAULT

    pagination_size_min = 1
    pagination_size_max = 60

    pagination_size = validate_numeric_param_value(pagination_size,
                                                   pagination_size_min,
                                                   pagination_size_max,
                                                   integer=True)
    return pagination_size


def get_datetime_from_iso8601(iso8601: str):
    """Returns a datetime object from an ISO 8601 formatted
    string, or raises a ValueError if the string is not valid
    ISO-8601 format.

    The API Gateway does not validate the format of input parameters.
    Some endpoints may require datetime objects from an ISO 8601
    timestamp.

    Use this function to convert the timestamp.
    """
    iso8601 = iso8601.replace("Z", "+00:00")
    return datetime.datetime.fromisoformat(iso8601)


def iso8601_to_utc(iso8601: str, timespec: str = "microseconds"):
    """Returns an ISO 8601 formatted string in UTC format.

    e.g.
    given:   2022-02-23T15:59:45.000000+03:00
    returns: 2022-02-23T12:59:45.000000Z

    This function expects an ISO 8601 date-time string and converts
    it to UTC time.
    """
    dt = get_datetime_from_iso8601(iso8601)
    utc_iso8601 = dt.astimezone(tz=datetime.timezone.utc).isoformat(
        timespec=timespec)
    utc_iso8601 = utc_iso8601.replace("+00:00", "Z")
    return utc_iso8601


def validate_user_access(user_guid: str, resource_guid: str, root_endpoint: str,
                         permissions_required: int,
                         request_headers: dict) -> None:
    """Raises an exception if the user does not have the requested
    permissions level, otherwise returns user's access level.

    Helper function to be called by validate_user_org_access() and
    validate_user_fleet_access().

    :param user_guid: the GUID for the user whose permissions are being
                      validated
    :param resource_guid: the GUID for the resource's GUID endpoint
    :param root_endpoint: root endpoint to call for the request.
    :param permissions_required: required permissions level for the user
    :param request_headers: request headers to use
    """

    payload = {"user_guid": user_guid}
    get_url = f"{root_endpoint}/{resource_guid}/users"
    get_response = requests.get(get_url,
                                headers=request_headers,
                                params=payload)

    if get_response.status_code == 404:
        raise ResourceNotFoundError(
            f"Resource GUID {resource_guid} does not exist, "
            " or user does not have permission to access it.")

    assert get_response.status_code == 200
    get_response_json = get_response.json()
    users = get_response_json.get("users")

    if not users:
        raise ResourceNotFoundError(
            f"Resource GUID {resource_guid} does not exist, "
            " or user does not have permission to access it.")

    user_access = users[0]["access"]

    if permissions_required is not None and user_access < permissions_required:
        raise PermissionsError("User does not have permissions"
                               " to perform this action.")

    return user_access


def validate_user_org_access(user_guid: str, org_guid: str,
                             permissions_required: int, rest_api_path: str,
                             request_headers: dict) -> None:
    """Raises an exception if the user does not have the requested
    permissions level, otherwise returns access level.

    Because videon_shared is a lambda layer, we cannot set environment
    variables, so the request url and headers must be passed into the function.

    Use this function to validate a user meets the required permissions level
    in an organization or pass None for permissions_required to obtain their
    access level in the organization.
    """
    return validate_user_access(user_guid, org_guid, f"{rest_api_path}orgs",
                                permissions_required, request_headers)


def validate_user_fleet_access(user_guid: str, fleet_guid: str,
                               permissions_required: int, rest_api_path: str,
                               request_headers: dict) -> None:
    """Raises an exception if the user does not have the requested
    permissions level, otherwise returns access level.

    Because videon_shared is a lambda layer, we cannot set environment
    variables, so the request url and headers must be passed into the function.

    Use this function to validate a user meets the required permissions level
    in a fleet or pass None for permissions_required to obtain their access
    level in the fleet.
    """
    return validate_user_access(user_guid, fleet_guid, f"{rest_api_path}fleets",
                                permissions_required, request_headers)
