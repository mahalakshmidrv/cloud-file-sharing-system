"""Cloud-Based File Sharing System - Flask application.

Features: user accounts, upload/download, per-user quota, share with other users,
expiring public links, activity log, local or S3 storage.
"""
import hashlib
import mimetypes
import os
import re
import secrets
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

import db
from config import Config
from storage import make_storage

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
EXPIRY_CHOICES = {"1h": 1, "24h": 24, "7d": 24 * 7, "30d": 24 * 30, "never": None}


def now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.isoformat(timespec="seconds")


def parse_iso(value):
    return datetime.fromisoformat(value) if value else None


def human_size(num):
    num = float(num)
    for unit in ("B", "KB", "MB", "GB"):
        if num < 1024 or unit == "GB":
            return f"{int(num)} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024


def create_app(config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if config:
        app.config.update(config)

    os.makedirs(os.path.dirname(app.config["DATABASE"]) or ".", exist_ok=True)
    db.init_app(app)
    app.extensions["storage"] = make_storage(app.config)
    failed_logins = {}  # (ip, username) -> [count, first_attempt_ts]

    # ------------------------------------------------------------------ helpers
    def storage():
        return app.extensions["storage"]

    def log(action, detail="", user_id=None):
        uid = user_id if user_id is not None else (g.user["id"] if g.get("user") else None)
        db.get_db().execute(
            "INSERT INTO activity (user_id, action, detail, created_at) VALUES (?,?,?,?)",
            (uid, action, detail, iso(now())),
        )
        db.get_db().commit()

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                flash("Please log in to continue.", "info")
                return redirect(url_for("login", next=request.path))
            return view(*args, **kwargs)
        return wrapped

    def get_file_or_404(file_id):
        row = db.get_db().execute(
            "SELECT f.*, u.username AS owner_name FROM files f "
            "JOIN users u ON u.id = f.owner_id WHERE f.id = ?", (file_id,)
        ).fetchone()
        if row is None:
            abort(404)
        return row

    def can_access(file_row):
        if file_row["owner_id"] == g.user["id"]:
            return True
        hit = db.get_db().execute(
            "SELECT 1 FROM shares WHERE file_id = ? AND user_id = ?",
            (file_row["id"], g.user["id"]),
        ).fetchone()
        return hit is not None

    def owned_file_or_404(file_id):
        row = get_file_or_404(file_id)
        if row["owner_id"] != g.user["id"]:
            abort(404)  # do not reveal that the file exists
        return row

    def used_bytes(user_id):
        row = db.get_db().execute(
            "SELECT COALESCE(SUM(size), 0) AS total FROM files WHERE owner_id = ?", (user_id,)
        ).fetchone()
        return row["total"]

    def link_state(link):
        if link["revoked"]:
            return "revoked"
        exp = parse_iso(link["expires_at"])
        if exp and now() > exp:
            return "expired"
        return "active"

    # ------------------------------------------------------------ request hooks
    @app.before_request
    def load_user_and_check_csrf():
        g.user = None
        uid = session.get("user_id")
        if uid:
            g.user = db.get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
            if g.user is None:
                session.clear()
        if app.config["CSRF_ENABLED"] and request.method == "POST":
            sent = request.form.get("csrf_token", "")
            expected = session.get("csrf_token", "")
            if not expected or not secrets.compare_digest(sent, expected):
                abort(400, "Invalid or missing CSRF token. Reload the page and try again.")

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        return resp

    @app.context_processor
    def inject_globals():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(16)
        return {"csrf_token": session["csrf_token"], "current_user": g.get("user")}

    app.jinja_env.filters["filesize"] = human_size
    app.jinja_env.filters["pretty_time"] = (
        lambda v: parse_iso(v).strftime("%d %b %Y, %H:%M UTC") if v else "never"
    )

    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(413)
    def handle_errors(err):
        messages = {
            400: getattr(err, "description", "Bad request"),
            404: "That page or file could not be found.",
            413: "That upload is too large.",
        }
        return render_template("error.html", code=err.code, message=messages[err.code]), err.code

    # ------------------------------------------------------------------- auth
    @app.route("/")
    def index():
        return redirect(url_for("dashboard" if g.user else "login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm", "")
            error = None
            if not USERNAME_RE.match(username):
                error = "Username must be 3-30 characters: letters, numbers, underscore."
            elif not EMAIL_RE.match(email):
                error = "Please enter a valid email address."
            elif len(password) < 8:
                error = "Password must be at least 8 characters."
            elif password != confirm:
                error = "Passwords do not match."
            else:
                clash = db.get_db().execute(
                    "SELECT 1 FROM users WHERE username = ? OR email = ?", (username, email)
                ).fetchone()
                if clash:
                    error = "That username or email is already registered."
            if error:
                flash(error, "error")
                return render_template("register.html", username=username, email=email), 400
            cur = db.get_db().execute(
                "INSERT INTO users (username, email, password_hash, created_at) VALUES (?,?,?,?)",
                (username, email, generate_password_hash(password), iso(now())),
            )
            db.get_db().commit()
            log("register", f"New account {username}", user_id=cur.lastrowid)
            flash("Account created. You can log in now.", "success")
            return redirect(url_for("login"))
        return render_template("register.html", username="", email="")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            key = (request.remote_addr, username.lower())
            count, first = failed_logins.get(key, [0, 0])
            if count >= app.config["MAX_LOGIN_ATTEMPTS"]:
                if time.time() - first < app.config["LOGIN_LOCKOUT_SECONDS"]:
                    flash("Too many failed attempts. Try again in a few minutes.", "error")
                    return render_template("login.html", username=username), 429
                failed_logins.pop(key, None)
            user = db.get_db().execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                failed_logins.pop(key, None)
                session.clear()  # prevent session fixation
                session["user_id"] = user["id"]
                session["csrf_token"] = secrets.token_hex(16)
                g.user = user
                log("login", "Logged in")
                nxt = request.args.get("next", "")
                if not nxt.startswith("/") or nxt.startswith("//"):
                    nxt = url_for("dashboard")
                return redirect(nxt)
            failed_logins[key] = [count + 1, first or time.time()]
            flash("Incorrect username or password.", "error")
            return render_template("login.html", username=username), 401
        return render_template("login.html", username="")

    @app.post("/logout")
    def logout():
        if g.user:
            log("logout", "Logged out")
        session.clear()
        flash("You have been logged out.", "info")
        return redirect(url_for("login"))

    # -------------------------------------------------------------- dashboard
    @app.route("/dashboard")
    @login_required
    def dashboard():
        q = request.args.get("q", "").strip()
        sql = "SELECT * FROM files WHERE owner_id = ?"
        params = [g.user["id"]]
        if q:
            sql += " AND original_name LIKE ? ESCAPE '\\'"
            params.append("%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
        sql += " ORDER BY uploaded_at DESC, id DESC"
        files = db.get_db().execute(sql, params).fetchall()
        used = used_bytes(g.user["id"])
        quota = app.config["USER_QUOTA_BYTES"]
        return render_template(
            "dashboard.html", files=files, q=q, used=used, quota=quota,
            percent=min(100, int(used * 100 / quota)) if quota else 0,
            max_upload=app.config["MAX_CONTENT_LENGTH"],
        )

    @app.post("/upload")
    @login_required
    def upload():
        uploads = [f for f in request.files.getlist("files") if f and f.filename]
        if not uploads:
            flash("Choose at least one file to upload.", "error")
            return redirect(url_for("dashboard"))
        quota = app.config["USER_QUOTA_BYTES"]
        stored = 0
        for incoming in uploads:
            name = secure_filename(incoming.filename) or "file"
            ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
            if ext in app.config["BLOCKED_EXTENSIONS"]:
                flash(f"'{name}' was skipped: .{ext} files are not allowed.", "error")
                continue
            sha = hashlib.sha256()
            size = 0
            with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as tmp:
                while True:
                    chunk = incoming.stream.read(65536)
                    if not chunk:
                        break
                    sha.update(chunk)
                    size += len(chunk)
                    tmp.write(chunk)
                if size == 0:
                    flash(f"'{name}' was skipped: the file is empty.", "error")
                    continue
                if used_bytes(g.user["id"]) + size > quota:
                    flash(f"'{name}' was skipped: it would exceed your {human_size(quota)} quota.", "error")
                    continue
                tmp.seek(0)
                key = uuid.uuid4().hex
                storage().put(tmp, key)
            mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
            db.get_db().execute(
                "INSERT INTO files (owner_id, original_name, stored_key, size, mime_type, sha256, uploaded_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (g.user["id"], name, key, size, mime, sha.hexdigest(), iso(now())),
            )
            db.get_db().commit()
            log("upload", f"{name} ({human_size(size)})")
            stored += 1
        if stored:
            flash(f"Uploaded {stored} file{'s' if stored != 1 else ''}.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/download/<int:file_id>")
    @login_required
    def download(file_id):
        row = get_file_or_404(file_id)
        if not can_access(row):
            abort(404)
        log("download", row["original_name"])
        return storage().response(row["stored_key"], row["original_name"], row["mime_type"])

    @app.post("/files/<int:file_id>/rename")
    @login_required
    def rename(file_id):
        row = owned_file_or_404(file_id)
        new_name = secure_filename(request.form.get("name", "")) or ""
        if not new_name:
            flash("Enter a valid file name.", "error")
        else:
            db.get_db().execute("UPDATE files SET original_name = ? WHERE id = ?", (new_name, row["id"]))
            db.get_db().commit()
            log("rename", f"{row['original_name']} -> {new_name}")
            flash("File renamed.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/files/<int:file_id>/delete")
    @login_required
    def delete(file_id):
        row = owned_file_or_404(file_id)
        storage().delete(row["stored_key"])
        db.get_db().execute("DELETE FROM files WHERE id = ?", (row["id"],))
        db.get_db().commit()
        log("delete", row["original_name"])
        flash(f"Deleted {row['original_name']}.", "success")
        return redirect(url_for("dashboard"))

    # ---------------------------------------------------------------- sharing
    @app.route("/files/<int:file_id>/share")
    @login_required
    def share_page(file_id):
        row = owned_file_or_404(file_id)
        d = db.get_db()
        shares = d.execute(
            "SELECT s.id, s.created_at, u.username FROM shares s "
            "JOIN users u ON u.id = s.user_id WHERE s.file_id = ? ORDER BY s.created_at DESC",
            (file_id,),
        ).fetchall()
        links = [
            {"row": l, "state": link_state(l),
             "url": url_for("public_page", token=l["token"], _external=True)}
            for l in d.execute(
                "SELECT * FROM links WHERE file_id = ? ORDER BY created_at DESC", (file_id,)
            ).fetchall()
        ]
        return render_template("share.html", file=row, shares=shares, links=links,
                               expiry_choices=list(EXPIRY_CHOICES))

    @app.post("/files/<int:file_id>/share/user")
    @login_required
    def share_with_user(file_id):
        row = owned_file_or_404(file_id)
        username = request.form.get("username", "").strip()
        target = db.get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if target is None:
            flash("No user with that username.", "error")
        elif target["id"] == g.user["id"]:
            flash("You already own this file.", "error")
        else:
            cur = db.get_db().execute(
                "INSERT OR IGNORE INTO shares (file_id, user_id, created_at) VALUES (?,?,?)",
                (row["id"], target["id"], iso(now())),
            )
            db.get_db().commit()
            if cur.rowcount:
                log("share", f"{row['original_name']} -> {target['username']}")
                flash(f"Shared with {target['username']}.", "success")
            else:
                flash(f"Already shared with {target['username']}.", "info")
        return redirect(url_for("share_page", file_id=file_id))

    @app.post("/files/<int:file_id>/share/<int:share_id>/remove")
    @login_required
    def unshare(file_id, share_id):
        row = owned_file_or_404(file_id)
        db.get_db().execute("DELETE FROM shares WHERE id = ? AND file_id = ?", (share_id, row["id"]))
        db.get_db().commit()
        log("unshare", row["original_name"])
        flash("Access removed.", "success")
        return redirect(url_for("share_page", file_id=file_id))

    @app.post("/files/<int:file_id>/link")
    @login_required
    def create_link(file_id):
        row = owned_file_or_404(file_id)
        choice = request.form.get("expiry", "24h")
        if choice not in EXPIRY_CHOICES:
            choice = "24h"
        hours = EXPIRY_CHOICES[choice]
        expires = iso(now() + timedelta(hours=hours)) if hours else None
        db.get_db().execute(
            "INSERT INTO links (file_id, token, expires_at, created_at) VALUES (?,?,?,?)",
            (row["id"], secrets.token_urlsafe(24), expires, iso(now())),
        )
        db.get_db().commit()
        log("link_create", f"{row['original_name']} (expires: {choice})")
        flash("Public link created.", "success")
        return redirect(url_for("share_page", file_id=file_id))

    @app.post("/files/<int:file_id>/link/<int:link_id>/revoke")
    @login_required
    def revoke_link(file_id, link_id):
        row = owned_file_or_404(file_id)
        db.get_db().execute("UPDATE links SET revoked = 1 WHERE id = ? AND file_id = ?", (link_id, row["id"]))
        db.get_db().commit()
        log("link_revoke", row["original_name"])
        flash("Link revoked.", "success")
        return redirect(url_for("share_page", file_id=file_id))

    @app.route("/shared")
    @login_required
    def shared_with_me():
        files = db.get_db().execute(
            "SELECT f.*, u.username AS owner_name, s.created_at AS shared_at FROM shares s "
            "JOIN files f ON f.id = s.file_id JOIN users u ON u.id = f.owner_id "
            "WHERE s.user_id = ? ORDER BY s.created_at DESC", (g.user["id"],)
        ).fetchall()
        return render_template("shared.html", files=files)

    # ------------------------------------------------------------ public links
    def active_link_or_none(token):
        link = db.get_db().execute(
            "SELECT l.*, f.original_name, f.size, f.mime_type, f.stored_key, f.sha256, "
            "u.username AS owner_name FROM links l JOIN files f ON f.id = l.file_id "
            "JOIN users u ON u.id = f.owner_id WHERE l.token = ?", (token,)
        ).fetchone()
        if link is None:
            return None, "missing"
        state = link_state(link)
        return (link if state == "active" else None), state

    @app.route("/s/<token>")
    def public_page(token):
        link, state = active_link_or_none(token)
        if state == "missing":
            abort(404)
        if link is None:
            return render_template("public.html", link=None, state=state), 410
        return render_template("public.html", link=link, state=state)

    @app.route("/s/<token>/download")
    def public_download(token):
        link, state = active_link_or_none(token)
        if state == "missing":
            abort(404)
        if link is None:
            return render_template("public.html", link=None, state=state), 410
        db.get_db().execute("UPDATE links SET downloads = downloads + 1 WHERE id = ?", (link["id"],))
        db.get_db().commit()
        log("public_download", link["original_name"], user_id=None)
        return storage().response(link["stored_key"], link["original_name"], link["mime_type"])

    # --------------------------------------------------------------- activity
    @app.route("/activity")
    @login_required
    def activity():
        rows = db.get_db().execute(
            "SELECT * FROM activity WHERE user_id = ? ORDER BY id DESC LIMIT 100", (g.user["id"],)
        ).fetchall()
        return render_template("activity.html", rows=rows)

    return app


if __name__ == "__main__":
    create_app().run(host=os.environ.get("HOST", "127.0.0.1"),
                     port=int(os.environ.get("PORT", "5000")),
                     debug=os.environ.get("FLASK_DEBUG") == "1")
