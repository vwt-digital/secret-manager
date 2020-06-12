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
