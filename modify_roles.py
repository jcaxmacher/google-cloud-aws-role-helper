"""
Modify the AWS IAM roles associated with a Google Apps Directory User

Example usage:

$ python modify_roles.py <aws credential profile name> \
    <SAML provider name in AWS> <email address> <ADD or REMOVE> <AWS role name>
"""
from __future__ import print_function
import os
import sys
from io import StringIO
from pprint import pprint
from contextlib import contextmanager

import boto3
from googleapiclient.discovery import build
from httplib2 import Http
from oauth2client import file, client, tools


SCOPES = 'https://www.googleapis.com/auth/admin.directory.user'


@contextmanager
def write_files(aws_profile):
    """Write credentials files for Google Apps access"""
    script_path = os.path.dirname(os.path.realpath(__file__))
    session = boto3.Session(profile_name=aws_profile)
    client = session.client('secretsmanager')
    print('Getting Google Apps token')
    token = client.get_secret_value(SecretId='GoogleAppsToken')['SecretString']
    with open(os.path.join(script_path, 'token.json'), 'w') as f:
        f.write(token)
    print('Getting Google Apps credentials')
    credentials = client.get_secret_value(SecretId='GoogleAppsCredentials')['SecretString']
    with open(os.path.join(script_path, 'credentials.json'), 'w') as f:
        f.write(credentials)
    yield
    print('Removing token.json and credentials.json')
    os.remove(os.path.join(script_path, 'token.json'))
    os.remove(os.path.join(script_path, 'credentials.json'))


def get_role_arn_template(aws_profile, saml_provider):
    """Create a role arn template using the AWS account ID."""
    session = boto3.Session(profile_name=aws_profile)
    client = session.client('sts')
    print('Getting AWS account ID')
    identity = client.get_caller_identity()
    account_id = identity['Account']
    samlprovider_arn = 'arn:aws:iam::{}:saml-provider/{}'.format(
        account_id, saml_provider
    )
    role_arn_template = 'arn:aws:iam::{}:role/{},{}'.format(
        account_id, '{}', samlprovider_arn
    )
    return role_arn_template


def modify_roles(aws_profile, saml_provider, user_key, action, role_name):
    """Add or remove an IAM Role from a user in the Google Directory"""
    role_arn_template = get_role_arn_template(aws_profile, saml_provider)
    store = file.Storage('token.json')
    creds = store.get()
    if not creds or creds.invalid:
        flow = client.flow_from_clientsecrets('credentials.json', SCOPES)
        creds = tools.run_flow(flow, store)
    service = build('admin', 'directory_v1', http=creds.authorize(Http()))
    user = service.users().\
        get(userKey=user_key, projection='full').execute()
    roles = user['customSchemas']['sso']['role']
    role_arn = role_arn_template.format(role_name)
    roles = [
        role for role in roles
        if role['value'].lower() != role_arn.lower()
    ]
    if action == 'ADD':
        roles.append({
            'type': 'work',
            'customType': role_name,
            'value': role_arn
        })
    output = StringIO()
    pprint(roles, stream=output)
    output.seek(0)
    print('Updating SSO Roles to: \n', output.read())
    service.users().\
        patch(userKey=user_key,
              body={'customSchemas': {'sso': {'role': roles}}}).execute()


if __name__ == '__main__':
    aws_profile, saml_provider, user_key, action, role_name = sys.argv[1:]
    with write_files(aws_profile):
        modify_roles(aws_profile, saml_provider, user_key, action, role_name)
