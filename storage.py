"""Pluggable storage backends: local disk (default) or Amazon S3."""
import os
import shutil

from flask import Response, send_file


class LocalStorage:
    """Stores files on the server's disk."""

    name = "local"

    def __init__(self, root):
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)

    def _path(self, key):
        path = os.path.abspath(os.path.join(self.root, key))
        if os.path.commonpath([self.root, path]) != self.root:
            raise ValueError("Invalid storage key")
        return path

    def put(self, fileobj, key):
        with open(self._path(key), "wb") as out:
            shutil.copyfileobj(fileobj, out)

    def delete(self, key):
        try:
            os.remove(self._path(key))
        except FileNotFoundError:
            pass

    def exists(self, key):
        return os.path.exists(self._path(key))

    def response(self, key, download_name, mimetype):
        return send_file(
            self._path(key),
            as_attachment=True,
            download_name=download_name,
            mimetype=mimetype,
        )


class S3Storage:
    """Stores files in an S3 bucket (needs `pip install boto3` and AWS credentials)."""

    name = "s3"

    def __init__(self, bucket, region, prefix=""):
        try:
            import boto3  # imported lazily so local mode needs no AWS libs
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("STORAGE_BACKEND=s3 requires boto3: pip install boto3") from exc
        if not bucket:
            raise RuntimeError("S3_BUCKET must be set when STORAGE_BACKEND=s3")
        self.bucket = bucket
        self.prefix = prefix
        self.client = boto3.client("s3", region_name=region)

    def _k(self, key):
        return f"{self.prefix}{key}"

    def put(self, fileobj, key):  # pragma: no cover - needs AWS
        self.client.upload_fileobj(
            fileobj, self.bucket, self._k(key),
            ExtraArgs={"ServerSideEncryption": "AES256"},
        )

    def delete(self, key):  # pragma: no cover
        self.client.delete_object(Bucket=self.bucket, Key=self._k(key))

    def exists(self, key):  # pragma: no cover
        try:
            self.client.head_object(Bucket=self.bucket, Key=self._k(key))
            return True
        except Exception:
            return False

    def response(self, key, download_name, mimetype):  # pragma: no cover
        obj = self.client.get_object(Bucket=self.bucket, Key=self._k(key))
        resp = Response(obj["Body"].iter_chunks(chunk_size=65536), mimetype=mimetype)
        resp.headers["Content-Length"] = str(obj["ContentLength"])
        resp.headers["Content-Disposition"] = f'attachment; filename="{download_name}"'
        return resp


def make_storage(config):
    backend = config.get("STORAGE_BACKEND", "local").lower()
    if backend == "s3":
        return S3Storage(config["S3_BUCKET"], config["S3_REGION"], config.get("S3_PREFIX", ""))
    return LocalStorage(config["UPLOAD_FOLDER"])
