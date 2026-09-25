"""CVSS scoring rules for supported ThreatSentinel alert types."""

import re


CVSS_VECTORS = {
    "ARP_MITM": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "ARP_FLOOD": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "ARP_SPOOFING": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "MAC_CONFLICT": "AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "ARP_GRATUITOUS": "AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L",
    "ARP_BROADCAST": "AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "ICMP_ECHO_REQUEST_FLOOD": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "ICMP_TIMESTAMP_REQUEST_FLOOD": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H",
    "ICMP_ADDRESS_MASK_REQUEST_FLOOD": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
    "ICMP_SMURF_ATTACK": "AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H",
    "SYN_SCAN": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "NULL_SCAN": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "FIN_SCAN": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "XMAS_SCAN": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N:A:N",
    "UDP_SCAN": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    "OS_FINGERPRINT": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "FULLPORT_SCAN": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "ACK_SCAN": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    "SPOOFED_SYN_FLOOD": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
}

ATTACK_MAPPING = {
    "ARP MITM": "ARP_MITM", "ARP FLOOD": "ARP_FLOOD", "ARP SPOOFING": "ARP_SPOOFING",
    "MAC CONFLICT": "MAC_CONFLICT", "GRATUITOUS_ARP": "ARP_GRATUITOUS",
    "BROADCAST_SPOOF": "ARP_BROADCAST", "ICMP ECHO REQUEST FLOOD": "ICMP_ECHO_REQUEST_FLOOD",
    "ICMP TIMESTAMP REQUEST FLOOD": "ICMP_TIMESTAMP_REQUEST_FLOOD",
    "ICMP ADDRESS MASK REQUEST FLOOD": "ICMP_ADDRESS_MASK_REQUEST_FLOOD",
    "SMURF ATTACK": "ICMP_SMURF_ATTACK", "SYN SCAN": "SYN_SCAN", "NULL SCAN": "NULL_SCAN",
    "FIN SCAN": "FIN_SCAN", "XMAS SCAN": "XMAS_SCAN", "UDP SCAN": "UDP_SCAN",
    "OS FINGERPRINT": "OS_FINGERPRINT", "FULL_PORT_SCAN": "FULLPORT_SCAN",
    "ACK SCAN": "ACK_SCAN", "SPOOFED_SYN_FLOOD": "SPOOFED_SYN_FLOOD",
    "ARP_SPOOF": "ARP_SPOOFING", "CACHE_OVERRIDE": "ARP_MITM",
    "SMURF_ATTACK": "ICMP_SMURF_ATTACK",
}


def calculate_cvss_score(vector):
    metrics = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
        "PR": {"N": {"U": 0.85, "C": 0.85}, "L": {"U": 0.62, "C": 0.68}, "H": {"U": 0.27, "C": 0.5}},
        "UI": {"N": 0.85, "R": 0.62}, "S": {"U": 6.42, "C": 7.52},
        "C": {"H": 0.56, "L": 0.22, "N": 0.0}, "I": {"H": 0.56, "L": 0.22, "N": 0.0},
        "A": {"H": 0.56, "L": 0.22, "N": 0.0},
    }
    try:
        parts = dict(metric.split(":") for metric in vector.split("/"))
        impact_subscore = 1 - ((1 - metrics["C"][parts["C"]]) * (1 - metrics["I"][parts["I"]]) * (1 - metrics["A"][parts["A"]]))
        impact = metrics["S"][parts["S"]] * impact_subscore
        exploitability = 8.22 * metrics["AV"][parts["AV"]] * metrics["AC"][parts["AC"]] * metrics["PR"][parts["PR"]][parts["S"]] * metrics["UI"][parts["UI"]]
        score = impact + exploitability
        return round(min(score * 1.08 if parts["S"] == "C" else score, 10), 1)
    except (AttributeError, KeyError, ValueError):
        return 0.0


def get_priority(score):
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    return "Low" if score > 0 else "None"


def process_alert(alert):
    raw_type = str(alert.get("alert_type", "")).strip().upper()
    normalized_type = re.sub(r"[\s-]+", "_", raw_type)
    attack_type = ATTACK_MAPPING.get(raw_type, ATTACK_MAPPING.get(normalized_type, normalized_type))
    vector = CVSS_VECTORS.get(attack_type)
    score = calculate_cvss_score(vector) if vector else 0.0
    return {
        "alert_id": str(alert.get("_id")), "attack_type": attack_type, "cvss_vector": vector,
        "cvss_score": score, "priority": get_priority(score),
        "source_ip": alert.get("src_ip", "N/A"), "target_ip": alert.get("target_ip", "N/A"),
        "timestamp": alert.get("start_time", "N/A"),
    }
