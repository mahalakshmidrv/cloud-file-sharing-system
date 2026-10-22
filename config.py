"""Application configuration. Every value can be overridden with an environment variable."""
import os
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")


def _load_secret_key():
    """Use SECRET_KEY from the environment, else create one once and keep it on disk
    so login sessions survive restarts."""
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    path = os.path.join(INSTANCE_DIR, "secret_key")
    if os.path.exists(path):
        with open(path) as fh:
            return fh.read().strip()
    key = secrets.token_hex(32)
    with open(path, "w") as fh:
        fh.write(key)
    return key


class Config:
    SECRET_KEY = _load_secret_key()
    DATABASE = os.environ.get("DATABASE", os.path.join(INSTANCE_DIR, "cloudshare.db"))

    # Storage backend: "local" (default) or "s3"
    STORAGE_BACKEND = os.environ.get("STORAGE_BACKEND", "local")
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", os.path.join(INSTANCE_DIR, "uploads"))
    S3_BUCKET = os.environ.get("S3_BUCKET", "")
    S3_REGION = os.environ.get("S3_REGION", "us-east-1")
    S3_PREFIX = os.environ.get("S3_PREFIX", "cloudshare/")

    # Limits
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_UPLOAD_MB", "50")) * 1024 * 1024
    USER_QUOTA_BYTES = int(os.environ.get("USER_QUOTA_MB", "200")) * 1024 * 1024
    BLOCKED_EXTENSIONS = {"exe", "bat", "cmd", "com", "scr", "msi", "ps1", "vbs", "jar"}

    # Security
    CSRF_ENABLED = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_LOCKOUT_SECONDS = 300
