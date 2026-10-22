import io
import os
import re
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app  # noqa: E402


class BaseCase(unittest.TestCase):
    csrf = False

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = create_app({
            "TESTING": True,
            "DATABASE": os.path.join(self.tmp.name, "test.db"),
            "UPLOAD_FOLDER": os.path.join(self.tmp.name, "uploads"),
            "CSRF_ENABLED": self.csrf,
            "SECRET_KEY": "test",
            "USER_QUOTA_BYTES": 1000,
            "MAX_LOGIN_ATTEMPTS": 3,
        })
        self.client = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    # helpers
    def register(self, client, name, password="password123"):
        return client.post("/register", data={
            "username": name, "email": f"{name}@example.com",
            "password": password, "confirm": password})

    def login(self, client, name, password="password123"):
        return client.post("/login", data={"username": name, "password": password})

    def new_user(self, name):
        c = self.app.test_client()
        self.register(c, name)
        self.login(c, name)
        return c

    def upload(self, client, name="hello.txt", content=b"hello world"):
        return client.post("/upload", data={"files": (io.BytesIO(content), name)},
                           content_type="multipart/form-data", follow_redirects=True)

    def file_id(self, owner_name="alice"):
        conn = sqlite3.connect(self.app.config["DATABASE"])
        row = conn.execute(
            "SELECT f.id FROM files f JOIN users u ON u.id=f.owner_id WHERE u.username=? "
            "ORDER BY f.id DESC", (owner_name,)).fetchone()
        conn.close()
        return row[0]

    def sql(self, query, params=()):
        conn = sqlite3.connect(self.app.config["DATABASE"])
        conn.execute(query, params)
        conn.commit()
        conn.close()


class AuthTests(BaseCase):
    def test_register_and_login(self):
        r = self.register(self.client, "alice")
        self.assertEqual(r.status_code, 302)
        r = self.login(self.client, "alice")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)

    def test_dashboard_requires_login(self):
        r = self.client.get("/dashboard")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])

    def test_duplicate_and_weak_passwords_rejected(self):
        self.register(self.client, "alice")
        self.assertEqual(self.register(self.client, "alice").status_code, 400)
        self.assertEqual(self.register(self.client, "bob", password="short").status_code, 400)

    def test_wrong_password(self):
        self.register(self.client, "alice")
        self.assertEqual(self.login(self.client, "alice", "wrongpass1").status_code, 401)

    def test_lockout_after_repeated_failures(self):
        self.register(self.client, "alice")
        for _ in range(3):
            self.login(self.client, "alice", "bad-password")
        self.assertEqual(self.login(self.client, "alice", "password123").status_code, 429)

    def test_open_redirect_blocked(self):
        self.register(self.client, "alice")
        r = self.client.post("/login?next=//evil.com",
                             data={"username": "alice", "password": "password123"})
        self.assertNotIn("evil.com", r.headers["Location"])

    def test_passwords_are_hashed(self):
        self.register(self.client, "alice")
        conn = sqlite3.connect(self.app.config["DATABASE"])
        stored = conn.execute("SELECT password_hash FROM users").fetchone()[0]
        conn.close()
        self.assertNotIn("password123", stored)


class FileTests(BaseCase):
    def setUp(self):
        super().setUp()
        self.alice = self.new_user("alice")

    def test_upload_and_download_roundtrip(self):
        r = self.upload(self.alice)
        self.assertIn(b"hello.txt", r.data)
        d = self.alice.get(f"/download/{self.file_id()}")
        self.assertEqual(d.status_code, 200)
        self.assertEqual(d.data, b"hello world")
        self.assertIn("attachment", d.headers["Content-Disposition"])

    def test_blocked_extension(self):
        r = self.upload(self.alice, "virus.exe", b"MZ")
        self.assertIn(b"not allowed", r.data)

    def test_empty_file_rejected(self):
        r = self.upload(self.alice, "empty.txt", b"")
        self.assertIn(b"empty", r.data)

    def test_quota_enforced(self):
        self.upload(self.alice, "a.bin", b"x" * 800)
        r = self.upload(self.alice, "b.bin", b"x" * 400)
        self.assertIn(b"quota", r.data)

    def test_path_traversal_filename_is_sanitised(self):
        self.upload(self.alice, "../../etc/passwd", b"data")
        conn = sqlite3.connect(self.app.config["DATABASE"])
        name = conn.execute("SELECT original_name FROM files").fetchone()[0]
        conn.close()
        self.assertNotIn("/", name)
        self.assertNotIn("..", name)

    def test_rename_and_delete(self):
        self.upload(self.alice)
        fid = self.file_id()
        self.alice.post(f"/files/{fid}/rename", data={"name": "renamed.txt"})
        self.assertIn(b"renamed.txt", self.alice.get("/dashboard").data)
        self.alice.post(f"/files/{fid}/delete")
        self.assertEqual(self.alice.get(f"/download/{fid}").status_code, 404)
        self.assertEqual(os.listdir(os.path.join(self.tmp.name, "uploads")), [])

    def test_search(self):
        self.upload(self.alice, "report.txt")
        self.upload(self.alice, "photo.png", b"png")
        r = self.alice.get("/dashboard?q=report")
        self.assertIn(b"report.txt", r.data)
        self.assertNotIn(b"photo.png", r.data)


class SharingTests(BaseCase):
    def setUp(self):
        super().setUp()
        self.alice = self.new_user("alice")
        self.bob = self.new_user("bob")
        self.upload(self.alice)
        self.fid = self.file_id()

    def test_unshared_file_is_private(self):
        self.assertEqual(self.bob.get(f"/download/{self.fid}").status_code, 404)
        self.assertEqual(self.bob.get(f"/files/{self.fid}/share").status_code, 404)
        self.assertEqual(self.bob.post(f"/files/{self.fid}/delete").status_code, 404)

    def test_share_with_user_then_revoke(self):
        self.alice.post(f"/files/{self.fid}/share/user", data={"username": "bob"})
        self.assertEqual(self.bob.get(f"/download/{self.fid}").data, b"hello world")
        self.assertIn(b"hello.txt", self.bob.get("/shared").data)
        # shared users cannot delete or re-share
        self.assertEqual(self.bob.post(f"/files/{self.fid}/delete").status_code, 404)
        conn = sqlite3.connect(self.app.config["DATABASE"])
        sid = conn.execute("SELECT id FROM shares").fetchone()[0]
        conn.close()
        self.alice.post(f"/files/{self.fid}/share/{sid}/remove")
        self.assertEqual(self.bob.get(f"/download/{self.fid}").status_code, 404)

    def test_share_unknown_user(self):
        r = self.alice.post(f"/files/{self.fid}/share/user", data={"username": "ghost"},
                            follow_redirects=True)
        self.assertIn(b"No user", r.data)

    def test_public_link_lifecycle(self):
        self.alice.post(f"/files/{self.fid}/link", data={"expiry": "24h"})
        conn = sqlite3.connect(self.app.config["DATABASE"])
        token, link_id = conn.execute("SELECT token, id FROM links").fetchone()
        conn.close()
        anon = self.app.test_client()
        self.assertEqual(anon.get(f"/s/{token}").status_code, 200)
        d = anon.get(f"/s/{token}/download")
        self.assertEqual(d.data, b"hello world")
        # revoke
        self.alice.post(f"/files/{self.fid}/link/{link_id}/revoke")
        self.assertEqual(anon.get(f"/s/{token}/download").status_code, 410)

    def test_expired_link(self):
        self.alice.post(f"/files/{self.fid}/link", data={"expiry": "1h"})
        past = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(timespec="seconds")
        self.sql("UPDATE links SET expires_at = ?", (past,))
        conn = sqlite3.connect(self.app.config["DATABASE"])
        token = conn.execute("SELECT token FROM links").fetchone()[0]
        conn.close()
        self.assertEqual(self.app.test_client().get(f"/s/{token}/download").status_code, 410)

    def test_unknown_token(self):
        self.assertEqual(self.app.test_client().get("/s/nope").status_code, 404)

    def test_activity_log_records_events(self):
        r = self.alice.get("/activity")
        self.assertIn(b"upload", r.data)


class CsrfTests(BaseCase):
    csrf = True

    def test_post_without_token_is_rejected(self):
        r = self.client.post("/register", data={"username": "x"})
        self.assertEqual(r.status_code, 400)

    def test_post_with_token_is_accepted(self):
        page = self.client.get("/register").get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
        r = self.client.post("/register", data={
            "csrf_token": token, "username": "carol", "email": "c@example.com",
            "password": "password123", "confirm": "password123"})
        self.assertEqual(r.status_code, 302)


if __name__ == "__main__":
    unittest.main()
