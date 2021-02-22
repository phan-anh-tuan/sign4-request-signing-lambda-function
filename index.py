# Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# This file is licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License. A copy of the
# License is located at
#
# http://aws.amazon.com/apache2.0/
#
# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
# OF ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.

# AWS Version 4 signing example

# See: http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
# This version makes a POST request and passes request parameters
# in the body (payload) of the request. Auth information is passed in
# an Authorization header.
import sys
import os
import base64
import datetime
import hashlib
import hmac
import requests  # pip install requests
import json
import http.client

# enable debugging
http.client.HTTPConnection.debuglevel = 1


def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def getSignatureKey(key, date_stamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), date_stamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning


# Read Lambda execution role credentials
access_key = os.environ.get('AWS_ACCESS_KEY_ID')
secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
session_token = os.environ.get('AWS_SESSION_TOKEN')


def main(event, context):
    # ************* REQUEST VALUES *************
    method = event['method']  # 'POST' or 'GET'
    # 'https://7a8juo2et9.execute-api.ap-southeast-2.amazonaws.com/live/signature-v4'
    endpoint = event['endpoint']

    if (method.upper() != 'POST' and method.upper() != 'GET') or (not endpoint.lower().startswith('https://')):
        raise Exception('Invalid payload')

    url_parts = endpoint[8:].split('/')
    # '7a8juo2et9.execute-api.ap-southeast-2.amazonaws.com'
    host = url_parts.pop(0)
    host_parts = host.split('.')

    # if (len(host_parts) != 5 or host_parts[1] != 'execute-api' or host_parts[3] != 'amazonaws' or host_parts[4] != 'com'):
    #     raise Exception('Invalid payload')

    service = 'execute-api'
    region = host_parts[2]  # 'ap-southeast-2'

    # POST requests use a content type header.
    content_type = 'application/json'

    request_parameters = ''
    if (method.upper() == 'POST'):
        request_parameters = json.dumps(event['payload'])

    # Create a date for headers and the credential string
    t = datetime.datetime.utcnow()
    amz_date = t.strftime('%Y%m%dT%H%M%SZ')
    # Date w/o time, used in credential scope
    date_stamp = t.strftime('%Y%m%d')

    # ************* TASK 1: CREATE A CANONICAL REQUEST *************
    # http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

    # Step 1 is to define the verb (GET, POST, etc.)--already done.

    # Step 2: Create canonical URI--the part of the URI from domain to query
    # string (use '/' if no path)
    canonical_uri = '/{}'.format('/'.join(url_parts))  # /live/signature-v4

    # Step 3: Create the canonical query string. In this example, request
    # parameters are passed in the body of the request and the query string
    # is blank.
    canonical_querystring = ''
    if (method.upper() == 'GET'):
        canonical_querystring = event['querystring']

    # Step 4: Create the canonical headers. Header names must be trimmed
    # and lowercase, and sorted in code point order from low to high.
    # Note that there is a trailing \n.
    canonical_headers = 'host:' + host + \
        '\n' + 'x-amz-date:' + amz_date + '\n' + \
        'x-amz-security-token:' + session_token + '\n'
    if (method.upper() == 'POST'):
        canonical_headers = 'content-type:' + content_type + '\n' + canonical_headers

    # Step 5: Create the list of signed headers. This lists the headers
    # in the canonical_headers list, delimited with ";" and in alpha order.
    # Note: The request can include any headers; canonical_headers and
    # signed_headers include those that you want to be included in the
    # hash of the request. "Host" and "x-amz-date" are always required.
    signed_headers = 'host;x-amz-date;x-amz-security-token'
    if (method.upper() == 'POST'):
        signed_headers = 'content-type;' + signed_headers

    # Step 6: Create payload hash. In this example, the payload (body of
    # the request) contains the request parameters.
    payload_hash = hashlib.sha256(
        request_parameters.encode('utf-8')).hexdigest()

    # Step 7: Combine elements to create canonical request
    canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + \
        '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash

    # ************* TASK 2: CREATE THE STRING TO SIGN*************
    # Match the algorithm to the hashing algorithm you use, either SHA-1 or
    # SHA-256 (recommended)
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = date_stamp + '/' + region + \
        '/' + service + '/' + 'aws4_request'
    string_to_sign = algorithm + '\n' + amz_date + '\n' + credential_scope + \
        '\n' + hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

    # ************* TASK 3: CALCULATE THE SIGNATURE *************
    # Create the signing key using the function defined above.
    signing_key = getSignatureKey(secret_key, date_stamp, region, service)

    # Sign the string_to_sign using the signing_key
    signature = hmac.new(signing_key, (string_to_sign).encode(
        'utf-8'), hashlib.sha256).hexdigest()

    # ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
    # Put the signature information in a header named Authorization.
    authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + \
        credential_scope + ', ' + 'SignedHeaders=' + \
        signed_headers + ', ' + 'Signature=' + signature

    headers = {
        'X-Amz-Date': amz_date,
        'X-Amz-Security-Token': session_token,
        'Authorization': authorization_header
    }

    if (method.upper() == 'POST'):
        headers['Content-Type'] = content_type

    if "headers" in event:
        headers = {**headers, **event['headers']}
    # ************* SEND THE REQUEST *************
    # print('\nBEGIN REQUEST++++++++++++++++++++++++++++++++++++')
    # print('Request URL = ' + endpoint)
    if (method.upper() == 'POST'):
        r = requests.post(endpoint, data=request_parameters, headers=headers)
    elif (method.upper() == 'GET'):
        request_url = endpoint + '?' + canonical_querystring
        r = requests.get(request_url, headers=headers)

    # print('\nRESPONSE++++++++++++++++++++++++++++++++++++')
    # print('Response code: %d\n' % r.status_code)
    # print(r.text)

    return r.text
