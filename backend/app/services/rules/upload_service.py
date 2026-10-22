"""Authenticated ZIP upload service used by the rule-generation workflow.

Runtime files live under the ignored ``data/`` directory. The HTTP
implementation is an importable backend service boundary.
"""

import getpass
import hashlib
import hmac
import io
import json
import os
import threading
import time
import zipfile
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, redirect, request, send_from_directory, url_for

from ...core.paths import CREDENTIALS_DIR, RULE_UPLOADS_DIR
from ...core.settings import settings


DEFAULT_UPLOAD_DIR = RULE_UPLOADS_DIR
DEFAULT_CREDS_FILE = CREDENTIALS_DIR / "upload_service.json"
PBKDF2_ROUNDS = 200_000
ALLOWED_UPLOAD_EXTENSIONS = {".zip"}


def make_hash(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS).hex()


def save_credentials(creds_file: Path, username: str, salt_hex: str, hash_hex: str) -> None:
    creds_file.parent.mkdir(parents=True, exist_ok=True)
    creds_file.write_text(
        json.dumps({"username": username, "salt": salt_hex, "hash": hash_hex}), encoding="utf-8"
    )
    try:
        os.chmod(creds_file, 0o600)
    except OSError:
        # Windows does not support POSIX file modes in the same way.
        pass


def load_credentials(creds_file: Path):
    if not creds_file.is_file():
        return None
    return json.loads(creds_file.read_text(encoding="utf-8"))


def ensure_credentials(creds_file: Path = DEFAULT_CREDS_FILE):
    creds = load_credentials(creds_file)
    if creds:
        return creds

    print("No credentials found. Let's create an admin user for the server.")
    username = input("Choose username: ").strip()
    while not username:
        username = input("Choose username (non-empty): ").strip()
    password = getpass.getpass("Choose password: ")
    password_confirmation = getpass.getpass("Confirm password: ")
    if password != password_confirmation:
        print("Passwords did not match. Aborting.")
        raise SystemExit(1)

    salt = os.urandom(16)
    save_credentials(creds_file, username, salt.hex(), make_hash(password, salt))
    print(f"Credentials saved to {creds_file} (file permission restricted).")
    return load_credentials(creds_file)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def list_uploaded_files(upload_dir: Path):
    files = []
    for path in sorted(upload_dir.iterdir() if upload_dir.is_dir() else []):
        if path.is_file():
            stat = path.stat()
            files.append(
                {
                    "filename": path.name,
                    "size": stat.st_size,
                    "mtime": int(stat.st_mtime),
                    "sha256": file_sha256(path),
                }
            )
    return files


def create_app(upload_dir: Path = DEFAULT_UPLOAD_DIR, creds_file: Path = DEFAULT_CREDS_FILE) -> Flask:
    """Build the upload application with explicit paths for testability."""
    upload_dir = Path(upload_dir)
    creds_file = Path(creds_file)
    upload_dir.mkdir(parents=True, exist_ok=True)

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = settings.max_upload_bytes
    app.config["UPLOAD_DIR"] = upload_dir
    app.config["CREDS_FILE"] = creds_file
    auth_failures = {}
    auth_failures_lock = threading.Lock()

    @app.after_request
    def add_security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    def check_auth(username: str, password: str) -> bool:
        creds = load_credentials(creds_file)
        if not creds or not hmac.compare_digest(username, creds.get("username", "")):
            return False
        try:
            expected = creds["hash"]
            actual = make_hash(password, bytes.fromhex(creds["salt"]))
        except (KeyError, ValueError):
            return False
        return hmac.compare_digest(actual, expected)

    def auth_rate_limited(client_ip: str) -> bool:
        now = time.monotonic()
        with auth_failures_lock:
            failures = [
                timestamp
                for timestamp in auth_failures.get(client_ip, [])
                if now - timestamp < settings.auth_failure_window_seconds
            ]
            auth_failures[client_ip] = failures
            return len(failures) >= settings.auth_max_failures

    def requires_auth(view):
        @wraps(view)
        def decorated(*args, **kwargs):
            client_ip = request.remote_addr or "unknown"
            auth = request.authorization
            if auth_rate_limited(client_ip):
                return jsonify({"status": "error", "message": "Too many authentication attempts"}), 429
            if not auth or not check_auth(auth.username, auth.password):
                with auth_failures_lock:
                    auth_failures.setdefault(client_ip, []).append(time.monotonic())
                return (
                    jsonify({"status": "error", "message": "Authentication required"}),
                    401,
                    {"WWW-Authenticate": 'Basic realm="Login Required"'},
                )
            with auth_failures_lock:
                auth_failures.pop(client_ip, None)
            return view(*args, **kwargs)

        return decorated

    @app.route("/")
    @requires_auth
    def root():
        return redirect(url_for("discover"))

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "uploads_dir": str(upload_dir)})

    @app.route("/discover", methods=["GET"])
    @requires_auth
    def discover():
        return jsonify({"status": "ok", "files": list_uploaded_files(upload_dir)})

    @app.route("/upload", methods=["POST"])
    @requires_auth
    def upload():
        if "file" not in request.files:
            return jsonify({"status": "error", "message": "no file part"}), 400
        uploaded_file = request.files["file"]
        if not uploaded_file.filename:
            return jsonify({"status": "error", "message": "empty filename"}), 400

        filename = Path(uploaded_file.filename).name
        if Path(filename).suffix.lower() not in ALLOWED_UPLOAD_EXTENSIONS:
            return jsonify({"status": "error", "message": "only ZIP uploads are allowed"}), 400

        data = uploaded_file.read()
        if not zipfile.is_zipfile(io.BytesIO(data)):
            return jsonify({"status": "error", "message": "uploaded file is not a valid ZIP archive"}), 400
        sha256 = hashlib.sha256(data).hexdigest()
        destination = upload_dir / filename

        if destination.exists():
            if file_sha256(destination) == sha256:
                return jsonify(
                    {"status": "duplicate", "message": "file already exists with same content", "filename": filename, "sha256": sha256}
                )
            stem, suffix = destination.stem, destination.suffix
            counter = 1
            while destination.exists():
                filename = f"{stem}-{counter}{suffix}"
                destination = upload_dir / filename
                counter += 1

        destination.write_bytes(data)
        try:
            os.chmod(destination, 0o640)
        except OSError:
            pass
        return jsonify({"status": "ok", "filename": filename, "sha256": sha256}), 201

    @app.route("/download/<path:filename>", methods=["GET"])
    @requires_auth
    def download(filename):
        return send_from_directory(upload_dir, filename, as_attachment=True)

    return app


app = create_app()


def main() -> None:
    if settings.file_server_bind_host not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError("Do not expose the Flask development server. Use a production WSGI server behind TLS.")
    ensure_credentials()
    print(f"Starting secure Flask upload server on http://{settings.file_server_bind_host}:5005")
    app.run(host=settings.file_server_bind_host, port=5005, debug=False)


if __name__ == "__main__":
    main()
