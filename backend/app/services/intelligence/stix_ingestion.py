"""Ingest STIX bundles from the local TAXII bundle directory into MongoDB."""

import json
import time

from ...core.settings import settings
from ...integrations.taxii.paths import TAXII_BUNDLES_DIR


class StixIngestionService:
    def __init__(self, repository, bundles_dir=TAXII_BUNDLES_DIR):
        self.repository = repository
        self.bundles_dir = bundles_dir
        self.processed_bundle_ids = set()

    def load_processed_bundles(self):
        self.processed_bundle_ids = self.repository.existing_bundle_ids()
        print(f"[+] Found {len(self.processed_bundle_ids)} existing bundles in MongoDB.")

    def ingest_once(self):
        self.bundles_dir.mkdir(parents=True, exist_ok=True)
        new_files = new_objects = skipped_files = 0

        for path in sorted(self.bundles_dir.glob("*.json")):
            try:
                bundle = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                print(f"[x] Cannot read {path.name}: {exc}")
                continue

            bundle_id = bundle.get("id")
            if not bundle_id or bundle.get("type") != "bundle":
                print(f"[x] Skipping invalid STIX bundle: {path.name}")
                skipped_files += 1
                continue
            if bundle_id in self.processed_bundle_ids or self.repository.bundle_exists(bundle_id):
                skipped_files += 1
                continue

            try:
                object_count = self.repository.insert_bundle_objects(bundle_id, bundle.get("objects", []))
            except Exception as exc:
                print(f"[x] Failed to insert {path.name}: {exc}")
                continue

            self.processed_bundle_ids.add(bundle_id)
            new_files += 1
            new_objects += object_count
            print(f"[+] Inserted {object_count} objects from {path.name}")

        return new_files, new_objects, skipped_files


def create_service():
    from ...repositories.ioc_repository import IOCRepository

    return StixIngestionService(IOCRepository(settings.mongodb_uri))


def monitor(interval=30):
    service = create_service()
    service.load_processed_bundles()
    print(f"[+] Monitoring STIX bundles in {service.bundles_dir}")
    while True:
        new_files, new_objects, skipped_files = service.ingest_once()
        if new_files:
            print(f"[+] Ingested {new_objects} objects from {new_files} bundles.")
        elif not skipped_files:
            print("[!] No new STIX bundles found.")
        time.sleep(interval)


def main():
    monitor()


if __name__ == "__main__":
    main()
