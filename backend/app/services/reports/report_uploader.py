"""Safely upload generated ZIP archives to the authenticated upload service."""

import argparse
import getpass
import hashlib
import time
from pathlib import Path

from ...core.paths import RULE_EXPORTS_DIR
from ...core.settings import settings
from .report_paths import report_output_paths


DEFAULT_EXTRACTED_RULES_DIR = RULE_EXPORTS_DIR


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def discover_remote_files(session, server_url, auth):
    response = session.get(f"{server_url.rstrip('/')}/discover", auth=auth, timeout=10)
    response.raise_for_status()
    payload = response.json()
    if payload.get("status") != "ok":
        raise RuntimeError(f"Discover returned error: {payload}")
    return {entry["filename"]: entry.get("sha256") for entry in payload.get("files", [])}


def zip_files(*directories):
    for directory in directories:
        path = Path(directory)
        if not path.is_dir():
            continue
        yield from sorted(
            file_path for file_path in path.rglob("*") if file_path.is_file() and file_path.suffix.lower() == ".zip"
        )


def upload_new_archives(session, server_url, auth, directories, dry_run=False):
    """Upload archives whose content is not already available remotely.

    This intentionally never deletes remote files. If a same-named archive has
    different content, the server safely assigns a new filename.
    """
    remote_files = discover_remote_files(session, server_url, auth)
    remote_hashes = {sha256 for sha256 in remote_files.values() if sha256}
    results = []
    for archive in zip_files(*directories):
        digest = sha256_file(archive)
        if digest in remote_hashes:
            results.append({"file": archive.name, "status": "skipped", "reason": "already uploaded"})
            continue
        if dry_run:
            results.append({"file": archive.name, "status": "dry_run"})
            continue

        with archive.open("rb") as file_handle:
            response = session.post(
                f"{server_url.rstrip('/')}/upload",
                files={"file": (archive.name, file_handle)},
                auth=auth,
                timeout=30,
            )
        response.raise_for_status()
        payload = response.json()
        results.append({"file": archive.name, "status": payload.get("status", "success"), "response": payload})
        remote_hashes.add(digest)
    return results


def main():
    _, _, default_reports_zip = report_output_paths()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports", default=str(default_reports_zip), help="Directory containing report ZIP archives.")
    parser.add_argument("--extracted-rules", default=str(DEFAULT_EXTRACTED_RULES_DIR), help="Optional extracted-rule ZIP directory.")
    parser.add_argument("--server", default=settings.file_server_url, help="Upload service base URL.")
    parser.add_argument("--user", default=settings.file_server_username, help="Upload-service username.")
    parser.add_argument("--dry-run", action="store_true", help="List archives that would be uploaded.")
    parser.add_argument("--monitor", action="store_true", help="Continuously scan for archives to upload.")
    parser.add_argument("--poll-seconds", type=int, default=30, help="Seconds between monitor scans.")
    args = parser.parse_args()

    username = args.user or input("Server username: ").strip()
    password = settings.file_server_password or getpass.getpass("Server password: ")
    if not username or not password:
        raise RuntimeError("Upload-service credentials are required.")

    import requests

    if args.poll_seconds <= 0:
        raise RuntimeError("--poll-seconds must be positive.")
    while True:
        results = upload_new_archives(
            requests, args.server, (username, password), (args.reports, args.extracted_rules), args.dry_run
        )
        for result in results:
            print(f"[{result['status']}] {result['file']}")
        print(f"Processed {len(results)} archive(s).")
        if not args.monitor:
            break
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    main()
