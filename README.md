# Cloud-Based File Sharing System

A secure web application for storing files in the cloud and sharing them with other
users or through expiring public links. Built with **Python, Flask and SQLite**, with a
pluggable storage layer (local disk by default, **Amazon S3** optional).

## Features

| Area | What it does |
|---|---|
| Accounts | Register, log in/out, hashed passwords, session protection, login lockout after repeated failures |
| Files | Upload multiple files, download, rename, delete, search by name |
| Storage | Per-user quota, upload size limit, SHA-256 checksum for every file, blocked dangerous extensions (`.exe`, `.bat`, ...) |
| Sharing | Share a file with another registered user, remove access any time, "Shared with me" page |
| Public links | Create links that expire after 1 hour / 24 hours / 7 days / 30 days / never; revoke any time; download counter |
| Audit | Activity log of uploads, downloads, shares, logins |
| Security | CSRF protection on every form, safe filenames (no path traversal), files always served as downloads, security headers, private files return 404 to non-owners |
| Cloud | Switch storage to Amazon S3 (server-side encrypted) with environment variables |

## Project structure

```
CloudFileShare/
├── app.py              Flask app and all routes
├── config.py           Settings (all overridable by environment variables)
├── db.py               SQLite schema and helpers
├── storage.py          Local-disk and S3 storage backends
├── wsgi.py             Production entry point (gunicorn wsgi:app)
├── templates/          HTML pages (Jinja2)
├── static/style.css    Styling
├── tests/test_app.py   23 automated tests
├── requirements.txt
├── Dockerfile
├── run.bat / run.sh    One-click start scripts (Windows / Linux-macOS)
└── .env.example        Example configuration
```

## Quick start

### Windows (VS Code / Command Prompt)

Double-click `run.bat`, or run:

```bat
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

### Linux / macOS

```bash
./run.sh
# or manually:
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000**, click **Register**, create an account, and start uploading.
To try sharing, register a second account in a private/incognito window.

## Run the tests

```bash
python -m unittest discover -s tests -v
```

## Configuration

Set environment variables (see `.env.example`):

| Variable | Default | Meaning |
|---|---|---|
| `SECRET_KEY` | auto-generated, saved in `instance/secret_key` | Session signing key |
| `MAX_UPLOAD_MB` | 50 | Max size of one upload request |
| `USER_QUOTA_MB` | 200 | Storage per user |
| `STORAGE_BACKEND` | `local` | `local` or `s3` |
| `UPLOAD_FOLDER` | `instance/uploads` | Local storage directory |
| `S3_BUCKET`, `S3_REGION`, `S3_PREFIX` | - | Used when `STORAGE_BACKEND=s3` |
| `HOST`, `PORT` | 127.0.0.1, 5000 | Dev server address |

### Using Amazon S3

```bash
pip install boto3
export AWS_ACCESS_KEY_ID=...  AWS_SECRET_ACCESS_KEY=...
export STORAGE_BACKEND=s3  S3_BUCKET=my-bucket  S3_REGION=ap-south-1
python app.py
```

File contents go to S3; account and file metadata stay in SQLite. Note: the S3 backend
needs real AWS credentials and was not exercised by the automated tests.

## Deployment

```bash
docker build -t cloudshare .
docker run -p 8000:8000 -e SECRET_KEY=change-me -v cloudshare-data:/app/instance cloudshare
```

Or, on any Linux server / cloud VM: `gunicorn -w 3 -b 0.0.0.0:8000 wsgi:app` behind an
HTTPS reverse proxy (Nginx, Caddy, or a cloud load balancer). Always use HTTPS in production.

## How it works

1. **Upload**: the file is streamed to a temporary buffer while its size and SHA-256 are
   computed, the quota is checked, then it is stored under a random key (never the user's
   filename) in the storage backend. Metadata goes in SQLite.
2. **Access control**: every download checks "is this user the owner, or has the owner
   shared it with them?" Anyone else gets a 404.
3. **Public links**: a random 192-bit token maps to a file with an optional expiry time and
   a revoked flag. Anonymous visitors can only download through a valid, active token.

## Possible extensions

Folders, file versioning, password-protected links, email notifications, virus scanning,
per-file encryption, an admin dashboard, and a REST API.
