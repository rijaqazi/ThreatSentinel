# Running ThreatSentinel

Activate the project environment and configure `.env` before starting services.

```bash
cd ~/Desktop/ThreatSentinel
source .venv/bin/activate
```

## Normal local services

```bash
python3 scripts/launcher.py all
```

This starts the secure upload server, heartbeat API, TAXII server, and PCAP parser watcher.

## Full processing pipeline

```bash
python3 scripts/launcher.py all pipeline
```

`pipeline` adds the Nmap, ARP, and ICMP detector watchers; detector-alert ingestion; CVSS scoring; rule generation; IOC/STIX generation; and STIX ingestion. Use this only when MongoDB is configured through `MONGODB_URI`.

Press `Ctrl+C` once to stop every process started by the launcher.

## Optional live capture monitor

The live monitor is opt-in because it needs TShark capture permissions and an explicit network interface.

```bash
tshark -D
python3 new_detection/monitor_tshark_trigger.py --interface enp0s3
```

Replace `enp0s3` with an interface reported by `tshark -D`, or set `CAPTURE_INTERFACE` in `.env`.

## Central backend API

```bash
python3 -m backend.app.main
curl http://127.0.0.1:8000/api/v1/health
```

The expected response includes `"status": "ok"`.
