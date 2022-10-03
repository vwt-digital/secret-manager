# Secret Manager

Creates secrets in GCP Secret Manager across multiple projects.
This will also create and update the permission on secret level.
The actual content of a secret needs to be inserted by a user or by code.

## Usage

Some prerequisites:
* Create a secrets.json file.
* Enable Secret Manager API in your GCP projects.
* Ensure the service account you are using has the right permissions to manage secrets.

Run the python script:
```bash
python3 secrets.py -s secrets.json
```

Add a secret version:
```bash
echo -n "super-secret-string" | \
    gcloud secrets versions add "secret-id" --data-file=-
```

Get a secret version with python:
```python
from google.cloud import secretmanager

def get_secret(project_id, secret_id, version_id):

    client = secretmanager.SecretManagerServiceClient()

    name = client.secret_version_path(project_id, secret_id, version_id)
    response = client.access_secret_version(name)
    payload = response.payload.data.decode('UTF-8')

    return payload
```

