"""
Modify the AWS IAM roles associated with a Google Apps Directory User

Example usage:

$ python modify_roles.py <aws credential profile name> <email address> \
    <ADD or REMOVE> <AWS role name>
"""
from __future__ import print_function
import os
import sys
from io import StringIO
from pprint import pprint

import boto3
from googleapiclient.discovery import build
from httplib2 import Http
from oauth2client import file, client, tools


SCOPES = 'https://www.googleapis.com/auth/admin.directory.user'
SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))


def write_files(aws_profile):
    """Write credentials files for Google Apps access"""
    session = boto3.Session(profile_name=aws_profile)
    client = session.client('secretsmanager')
    print('Getting Google Apps token')
    token = client.get_secret_value(SecretId='GoogleAppsToken')['SecretString']
    with open(os.path.join(SCRIPT_PATH, 'token.json'), 'w') as f:
        f.write(token)
    print('Getting Google Apps credentials')
    credentials = client.get_secret_value(SecretId='GoogleAppsCredentials')['SecretString']
    with open(os.path.join(SCRIPT_PATH, 'credentials.json'), 'w') as f:
        f.write(credentials)


def get_role_arn_template(aws_profile):
    """Create a role arn template using the AWS account ID."""
    session = boto3.Session(profile_name=aws_profile)
    client = session.client('sts')
    print('Getting AWS account ID')
    identity = client.get_caller_identity()
    account_id = identity['Account']
    samlprovider_arn = 'arn:aws:iam::{}:saml-provider/GoogleApps'.format(
        account_id
    )
    role_arn_template = 'arn:aws:iam::{}:role/{},{}'.format(
        account_id, '{}', samlprovider_arn
    )
    return role_arn_template


def main(aws_profile, user_key, action, role_name):
    """Add or remove an IAM Role from a user in the Google Directory"""
    role_arn_template = get_role_arn_template(aws_profile)
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
    write_files(sys.argv[1])
    main(*sys.argv[1:])
    os.remove(os.path.join(SCRIPT_PATH, 'token.json'))
    os.remove(os.path.join(SCRIPT_PATH, 'credentials.json'))
