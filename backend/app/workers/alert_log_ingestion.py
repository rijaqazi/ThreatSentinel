"""Continuously merge detector logs and import each normalized alert into MongoDB once."""

import argparse
import hashlib
import json
import time
from pathlib import Path

from ..core.settings import settings
from ..repositories.alert_log_repository import AlertLogRepository
from ..services.alerts.alert_log_parser import parse_alert_line


def detector_log_paths(detector_output_dir):
    """Return individual detector logs, excluding the merged alert stream."""
    directory = Path(detector_output_dir)
    if not directory.is_dir():
        return []
    return sorted(path for path in directory.glob("*_alerts.log") if path.is_file())


def _read_new_lines(path, offset):
    size = path.stat().st_size
    offset = 0 if size < offset else offset
    with path.open("r", encoding="utf-8", errors="replace") as source:
        source.seek(offset)
        lines = source.readlines()
        return lines, source.tell()


def _fingerprint(alert):
    identity = {
        "alert_type": alert.get("alert_type"),
        "src_ip": alert.get("src_ip"),
        "target_ip": alert.get("target_ip"),
        "src_mac": alert.get("src_mac"),
        "ports": alert.get("ports"),
        "start_time": alert.get("start_time"),
        "duration_sec": alert.get("duration_sec"),
    }
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode("utf-8")).hexdigest()


def collect_new_alerts(detector_output_dir, merged_log_path, offsets):
    """Read only newly appended detector log lines and append them to a canonical log."""
    merged_log_path = Path(merged_log_path)
    merged_log_path.parent.mkdir(parents=True, exist_ok=True)
    alerts = []
    with merged_log_path.open("a", encoding="utf-8") as merged:
        for path in detector_log_paths(detector_output_dir):
            lines, offsets[path] = _read_new_lines(path, offsets.get(path, 0))
            for line in lines:
                alert = parse_alert_line(line)
                if not alert:
                    continue
                alert["source_fingerprint"] = _fingerprint(alert)
                alerts.append(alert)
                merged.write(line if line.endswith("\n") else f"{line}\n")
    return alerts


def ingest_once(detector_output_dir, merged_log_path, offsets, repository=None):
    alerts = collect_new_alerts(detector_output_dir, merged_log_path, offsets)
    repository = repository or AlertLogRepository("Alerts", "Alerts")
    return repository.upsert_alerts(alerts), len(alerts)


def monitor(detector_output_dir=None, merged_log_path=None, interval=None):
    detector_output_dir = detector_output_dir or settings.detector_output_dir
    merged_log_path = merged_log_path or settings.detector_alert_log_path
    interval = interval or settings.detector_alert_poll_seconds
    offsets = {}
    repository = AlertLogRepository("Alerts", "Alerts")
    print(f"[+] Monitoring detector logs in {detector_output_dir}")
    while True:
        imported, parsed = ingest_once(detector_output_dir, merged_log_path, offsets, repository)
        if parsed:
            print(f"[+] Imported {imported} new alert(s) from {parsed} parsed log line(s).")
        time.sleep(interval)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--detector-output-dir", default=str(settings.detector_output_dir))
    parser.add_argument("--merged-log", default=str(settings.detector_alert_log_path))
    parser.add_argument("--interval", type=int, default=settings.detector_alert_poll_seconds)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    if args.interval <= 0:
        raise SystemExit("--interval must be positive.")
    if args.once:
        imported, parsed = ingest_once(args.detector_output_dir, args.merged_log, {})
        print(f"Imported {imported} new alert(s) from {parsed} parsed log line(s).")
    else:
        monitor(args.detector_output_dir, args.merged_log, args.interval)


if __name__ == "__main__":
    main()
