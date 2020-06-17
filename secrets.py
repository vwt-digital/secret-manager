import json
import logging
import argparse

from googleapiclient import discovery
from oauth2client.client import GoogleCredentials
from google.cloud import secretmanager_v1

logging.basicConfig(level=logging.INFO, format='%(levelname)7s: %(message)s')


def read_secrets(path):
    """
    Read secrets from a secret.json file.
    """

    with open(path) as file:
        return json.load(file).get('projects', [])


def list_secrets(client, project_id):
    """
    List secrets for a given project.
    """

    parent = client.project_path(project_id)
    response = client.list_secrets(parent)

    return [secret.name.split('/')[-1] for secret in response]


def create_secret(client, project_id, secret_id):
    """
    Creates a secret in a project.
    """

    parent = client.project_path(project_id)
    response = client.create_secret(parent, secret_id, {
        'replication': {
            'automatic': {},
        },
    })

    logging.info('Created secret: {}'.format(response.name))


def delete_secret(client, project_id, secret_id):
    """
    Deletes a secret from a project.
    """

    name = client.secret_path(project_id, secret_id)
    client.delete_secret(name)

    logging.info('Deleted secret: {}'.format(name))


def list_secret_bindings(client, project_id, secret_id):
    """
    Returns the iam bindings for a secret.
    """

    name = client.secret_path(project_id, secret_id)
    policy = client.get_iam_policy(name)

    bindings = []
    for binding in policy.bindings:
        for member in binding.members:
            bindings.append({
                'role': binding.role,
                'member': member
            })

    return bindings


def delete_secret_binding(client, project_id, secret_id, role, member):
    """
    Revokes the given member access to a secret.
    """

    name = client.secret_path(project_id, secret_id)
    policy = client.get_iam_policy(name)

    for b in list(policy.bindings):
        if b.role == role and member in b.members:
            b.members.remove(member)

    client.set_iam_policy(name, policy)

    logging.info('Revoked {} role on {} for {}'.format(role, secret_id, member))


def create_secret_binding(client, project_id, secret_id, role, member):
    """
    Grant the given member access to a secret.
    """

    name = client.secret_path(project_id, secret_id)
    policy = client.get_iam_policy(name)

    policy.bindings.add(
        role=role,
        members=[member])

    client.set_iam_policy(name, policy)

    logging.info('Granted {} role on {} for {}'.format(role, secret_id, member))


def permissions_to_bindings(permissions, secret_id):
    """
    Converts Open Digital Rights Language permissions to bindings.
    """

    bindings = []
    for permission in permissions:
        if permission.get('target') == secret_id:
            bindings.append({
                'role': permission['action'],
                'member': permission['assignee']
            })

    return bindings


def get_project(service, project_id):
    """
    Returns a project dict given a project_id.
    """

    request = service.projects().get(projectId=project_id)
    response = request.execute()

    return response


def list_projects(service, filter):
    """
    Returns a list of projects matching a filter.
    """

    response = service.projects().list(filter=filter).execute()

    return response['projects']


def make_service():
    """
    Creates a cloudresourcemanager service.
    """

    credentials = GoogleCredentials.get_application_default()
    service = discovery.build('cloudresourcemanager', 'v1beta1', credentials=credentials)

    return service


def parse_args():
    """
    A simple function to parse command line arguments.
    """

    parser = argparse.ArgumentParser(description='GCP Secret Manager')
    parser.add_argument('-s', '--secrets-file',
                        required=True,
                        help='path to secrets.json file')
    parser.add_argument('-p', '--project-id',
                        required=True,
                        help='project id of the current project')
    return parser.parse_args()


def main(args):

    service = make_service()

    project = get_project(service, args.project_id)
    filter = 'parent.id:{}'.format(project['parent']['id'])
    projects = list_projects(service, filter)

    client = secretmanager_v1.SecretManagerServiceClient()
    secrets_doc = read_secrets(args.secrets_file)

    for project in projects:

        project_id = project['projectId']

        secrets = [item.get('secrets', []) for item in secrets_doc
                   if item['projectId'] == project_id]

        permissions = [item.get('odrlPolicy', {}).get('permission', []) for item in secrets_doc
                       if item['projectId'] == project_id]

        gcp_secrets = list_secrets(client, project_id)

        for secret_id in list(set(secrets) - set(gcp_secrets)):
            create_secret(client, project_id, secret_id)

        for secret_id in list(set(gcp_secrets) - set(secrets)):
            delete_secret(client, project_id, secret_id)

        gcp_secrets = list_secrets(client, project_id)

        for secret_id in gcp_secrets:
            bindings = permissions_to_bindings(permissions, secret_id)
            gcp_bindings = list_secret_bindings(client, project_id, secret_id)

            for binding in [i for i in bindings if i not in gcp_bindings]:
                create_secret_binding(client, project_id, secret_id, binding['role'], binding['member'])

            for binding in [i for i in gcp_bindings if i not in bindings]:
                delete_secret_binding(client, project_id, secret_id, binding['role'], binding['member'])


if __name__ == '__main__':
    main(parse_args())
