"""Parse detector alert logs into the normalized alert document shape."""

import re


def _match(pattern, line, default=None):
    match = re.search(pattern, line)
    return match.group(1) if match else default


def parse_alert_line(line):
    """Parse one ARP/ICMP/Nmap-style alert log line, or return ``None``."""
    line = line.strip()
    if not line or "ALERT" not in line:
        return None
    ports = _match(r"Ports:\s+([\d,\s]*)", line, "")
    duration = _match(r"Duration:\s+([\d.]+)s", line)
    alert_type = _match(r"(?:^|\s)-\s*(.*?)\s+ALERT\s+from\s", line)
    if not alert_type:
        alert_type = _match(r"\[ALERT\]\s*(.*?)\s+from\s", line)
    if alert_type:
        alert_type = alert_type.lstrip("- ")
    return {
        "timestamp": _match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line),
        "alert_type": alert_type,
        "type": alert_type,
        "src_ip": _match(r"from\s+([\d.]+)", line),
        "src_mac": _match(r"SRC_MAC:\s+([\w:]+|N/A)", line, "N/A"),
        "target_ip": _match(r"Target_IP:\s+([\d.]+|N/A)", line, "N/A"),
        "claimed_mac": _match(r"Claimed_MAC:\s+([\w:]+|N/A)", line, "N/A"),
        "previous_mac": _match(r"Previous_MAC:\s+([\w:]+|N/A)", line, "N/A"),
        "ports": [port.strip() for port in ports.split(",") if port.strip()],
        "ports_scanned_count": int(_match(r"Ports Scanned:\s+(\d+)", line, "0")),
        "start_time": _match(r"Start:\s+([\w:\- ]+)", line, "N/A"),
        "duration_sec": float(duration) if duration else 0.0,
    }


def parse_alert_log(path):
    with open(path, "r", encoding="utf-8") as file_handle:
        return [alert for line in file_handle if (alert := parse_alert_line(line))]
