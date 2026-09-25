"""Extract indicators from detector logs and generate local STIX bundles."""

import ipaddress
import json
import re
import time
import uuid
from collections import defaultdict
from pathlib import Path

from ..alerts.alert_log_parser import parse_alert_line


IOC_KEYS = ("ip_addresses", "mac_addresses", "domains", "urls", "hashes")
IP_CANDIDATE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC_ADDRESS = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")


def empty_iocs():
    return {key: [] for key in IOC_KEYS}


def _valid_ips(text):
    values = set()
    for candidate in IP_CANDIDATE.findall(text):
        try:
            values.add(str(ipaddress.ip_address(candidate)))
        except ValueError:
            continue
    return values


def extract_iocs_from_text(text):
    """Extract a deterministic, de-duplicated IOC document from arbitrary text."""
    return {
        "ip_addresses": sorted(_valid_ips(text)),
        "mac_addresses": sorted({value.lower() for value in MAC_ADDRESS.findall(text)}),
        "domains": sorted({value.lower() for value in DOMAIN.findall(text)}),
        "urls": sorted({value.rstrip(".,;:!?)]") for value in URL.findall(text)}),
        "hashes": sorted({value.lower() for value in SHA256.findall(text)}),
    }


def read_iocs(path):
    path = Path(path)
    if not path.is_file():
        return empty_iocs()
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty_iocs()
    return {key: list(document.get(key, [])) if isinstance(document, dict) else [] for key in IOC_KEYS}


def write_iocs(path, iocs):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    normalized = {key: sorted(set(iocs.get(key, []))) for key in IOC_KEYS}
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(normalized, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)
    return normalized


def update_iocs_from_log(log_file, output_file):
    """Merge indicators found in a detector log into the persistent IOC document."""
    try:
        text = Path(log_file).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    previous, extracted = read_iocs(output_file), extract_iocs_from_text(text)
    merged = {key: set(previous[key]) | set(extracted[key]) for key in IOC_KEYS}
    write_iocs(output_file, merged)
    return True


def load_whitelist(path):
    document = read_iocs(path)
    return {"ip_addresses": set(document["ip_addresses"]), "mac_addresses": set(document["mac_addresses"])}


def parse_alerts(log_file):
    """Parse the legacy detector alert-line format into normalized records."""
    alerts = []
    try:
        lines = Path(log_file).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return alerts
    for line in lines:
        parsed = parse_alert_line(line)
        if not parsed:
            continue
        alerts.append({
            "type": parsed["alert_type"] or "Unknown",
            "src_ip": parsed["src_ip"],
            "target_ip": parsed["target_ip"],
            "src_mac": parsed["src_mac"],
            "details": {
                "ports": ",".join(parsed["ports"]),
                "duration": str(parsed["duration_sec"]),
                "raw_log": line,
            },
        })
    return alerts


def _bundle_exists(ip_address, bundles_dir):
    marker = ip_address.replace(".", "_")
    return any(marker in path.name for path in Path(bundles_dir).glob("*.json"))


def generate_stix_bundles(log_file, ioc_file, whitelist_file, bundles_dir):
    """Create one STIX bundle per new, non-whitelisted alert source IP."""
    iocs, whitelist = read_iocs(ioc_file), load_whitelist(whitelist_file)
    matched = defaultdict(lambda: {"types": set(), "details": [], "macs": set()})
    for alert in parse_alerts(log_file):
        source = alert["src_ip"]
        source_mac = (alert["src_mac"] or "").lower()
        if not source or source not in iocs["ip_addresses"]:
            continue
        if source in whitelist["ip_addresses"] or source_mac in whitelist["mac_addresses"]:
            continue
        matched[source]["types"].add(alert["type"])
        matched[source]["details"].append(alert["details"])
        if source_mac:
            matched[source]["macs"].add(source_mac)

    bundles_dir = Path(bundles_dir)
    bundles_dir.mkdir(parents=True, exist_ok=True)
    created = []
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    run_time = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
    for source, info in matched.items():
        if _bundle_exists(source, bundles_dir):
            continue
        details = info["details"]
        ports = sorted({port.strip() for item in details for port in item["ports"].split(",") if port.strip()})
        raw_logs = sorted({item["raw_log"] for item in details if item["raw_log"]})
        indicator = {
            "type": "indicator", "id": f"indicator--{uuid.uuid4()}", "created": timestamp, "modified": timestamp,
            "name": "Malicious IP", "ip_address": source,
            "description": f"Threat types: {', '.join(sorted(info['types']))}; Ports: {', '.join(ports) or 'None'}; Raw logs: {len(raw_logs)}",
            "pattern": f"[ipv4-addr:value = '{source}']", "pattern_type": "stix", "valid_from": timestamp,
            "labels": ["malicious-activity"], "x_source_macs": sorted(info["macs"]), "x_raw_logs": raw_logs,
        }
        bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": [indicator]}
        destination = bundles_dir / f"stix_bundle_{source.replace('.', '_')}_{run_time}.json"
        destination.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
        created.append(destination)
    return created
