#!/usr/bin/env python3
"""Start selected local ThreatSentinel services from the project root."""

import argparse
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.core.settings import load_env_file

SERVICE_DEFINITIONS = {
    "upload": {
        "label": "secure upload server",
        "module": "backend.app.services.rules.upload_service",
        "cwd": PROJECT_ROOT,
        "port": 5005,
    },
    "heartbeat": {
        "label": "heartbeat server",
        "module": "backend.app.api.v1.heartbeats",
        "cwd": PROJECT_ROOT,
        "port": 5001,
    },
    "taxii": {
        "label": "TAXII server",
        "module": "backend.app.integrations.taxii.server",
        "cwd": PROJECT_ROOT,
        "port": 5002,
    },
    "capture": {
        "label": "PCAP parser watcher",
        "module": "backend.app.workers.capture.pcap_watch",
        "cwd": PROJECT_ROOT,
        "port": None,
    },
    "detector-nmap": {
        "label": "Nmap detector watcher",
        "module": "backend.app.workers.detectors.json_watch",
        "args": ["--detector", "nmap"],
        "cwd": PROJECT_ROOT,
        "port": None,
    },
    "detector-arp": {
        "label": "ARP detector watcher",
        "module": "backend.app.workers.detectors.json_watch",
        "args": ["--detector", "arp"],
        "cwd": PROJECT_ROOT,
        "port": None,
    },
    "detector-icmp": {
        "label": "ICMP detector watcher",
        "module": "backend.app.workers.detectors.json_watch",
        "args": ["--detector", "icmp"],
        "cwd": PROJECT_ROOT,
        "port": None,
    },
    "alerts": {
        "label": "detector alert ingestion worker",
        "module": "backend.app.workers.alert_log_ingestion",
        "cwd": PROJECT_ROOT,
        "port": None,
    },
    "cvss": {
        "label": "CVSS scoring worker",
        "module": "backend.app.workers.cvss_worker",
        "cwd": PROJECT_ROOT,
        "port": None,
    },
    "rules": {
        "label": "rule generation worker",
        "module": "backend.app.workers.rule_worker",
        "args": ["monitor"],
        "cwd": PROJECT_ROOT,
        "port": None,
    },
    "ioc": {
        "label": "IOC extraction and STIX worker",
        "module": "backend.app.workers.ioc_worker",
        "cwd": PROJECT_ROOT,
        "port": None,
    },
    "ingestion": {
        "label": "STIX ingestion worker",
        "module": "backend.app.services.intelligence.stix_ingestion",
        "cwd": PROJECT_ROOT,
        "port": None,
    },
}

DEFAULT_SERVICES = ("upload", "heartbeat", "taxii", "capture")
PIPELINE_SERVICES = (
    "detector-nmap",
    "detector-arp",
    "detector-icmp",
    "alerts",
    "cvss",
    "rules",
    "ioc",
    "ingestion",
)


def port_is_available(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return sock.connect_ex(("127.0.0.1", port)) != 0


def start_service(name):
    service = SERVICE_DEFINITIONS[name]
    if name == "upload" and not (PROJECT_ROOT / "data" / "credentials" / "upload_service.json").is_file():
        raise RuntimeError(
            "Upload credentials are not initialized. Run 'python3 -m backend.app.services.rules.upload_service' "
            "once, create the credentials, stop it, then rerun the launcher."
        )

    if service["port"] is not None and not port_is_available(service["port"]):
        raise RuntimeError(f"Port {service['port']} is already in use; {service['label']} was not started.")

    if service["port"] is None:
        print(f"[+] Starting {service['label']}...")
    else:
        print(f"[+] Starting {service['label']} on port {service['port']}...")
    kwargs = {
        "cwd": service["cwd"],
        "env": os.environ.copy(),
    }
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True

    command = [sys.executable, "-m", service["module"]] if "module" in service else [sys.executable, str(service["script"])]
    command.extend(service.get("args", []))
    process = subprocess.Popen(command, **kwargs)
    time.sleep(0.5)
    if process.poll() is not None:
        raise RuntimeError(f"{service['label']} exited immediately with code {process.returncode}.")
    if service["port"] is None:
        print(f"    PID {process.pid}")
    else:
        print(f"    PID {process.pid} | http://127.0.0.1:{service['port']}/")
    return process


def stop_process(process):
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.terminate()
        else:
            os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "services",
        nargs="*",
        choices=[*SERVICE_DEFINITIONS, "all", "pipeline"],
        default=["all"],
        help="Services to start. 'all' starts network services; add 'pipeline' for background workers.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if not load_env_file(PROJECT_ROOT / ".env"):
        print(f"[!] No .env file at {PROJECT_ROOT / '.env'}; using the current shell environment.")
    selected = []
    if "all" in args.services:
        selected.extend(DEFAULT_SERVICES)
    if "pipeline" in args.services:
        selected.extend(PIPELINE_SERVICES)
    selected.extend(service for service in args.services if service not in {"all", "pipeline"})
    selected = list(dict.fromkeys(selected))
    processes = []
    try:
        for service in selected:
            processes.append(start_service(service))
        print("[+] Selected services are running. Press Ctrl+C to stop them.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Stopping services...")
    finally:
        for process in reversed(processes):
            stop_process(process)
        if processes:
            print("[+] Services stopped.")


if __name__ == "__main__":
    main()

