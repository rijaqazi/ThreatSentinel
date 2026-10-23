# ThreatSentinel

ThreatSentinel is a proactive network-security and threat-intelligence platform. It processes controlled packet-capture evidence, detects suspicious Nmap, ARP, and ICMP activity, stores normalized alerts in MongoDB, assigns CVSS-based severity, generates defensive firewall rules, extracts Indicators of Compromise (IOCs), creates STIX bundles, and shares intelligence through TAXII.

Use this project only for defensive analysis on systems and networks that you own or are explicitly authorized to test.

## What the project does

```text
PCAP capture
  -> packet parsing
  -> Nmap / ARP / ICMP detection
  -> normalized MongoDB alerts
  -> CVSS scoring
  -> defensive rule generation
  -> IOC extraction and STIX generation
  -> TAXII sharing, dashboard, reports, and desktop rule tools
```

## Key features

- Flask dashboard for alerts, CVSS results, IOCs, and reports.
- PCAP/PCAPNG parsing with TShark/Wireshark support.
- Nmap, ARP, and ICMP detector workers.
- MongoDB Atlas storage for alerts, scores, IOCs, users, and organization data.
- CVSS scoring and priority assignment.
- Generated defensive firewall-rule JSON with a Tkinter Rule Editor.
- IOC extraction, STIX bundle generation, and TAXII 2.1 sharing.
- Authenticated local rule-upload service and protected TAXII endpoints.
- Pinned Python dependencies, environment-based secrets, and ignored runtime data.

## Final structure

```text
ThreatSentinel/
├── backend/
│   ├── app/
│   │   ├── api/v1/                  Health and heartbeat APIs
│   │   ├── core/                    Settings, environment loading, safe paths
│   │   ├── integrations/taxii/      TAXII 2.1 server and client code
│   │   ├── repositories/            MongoDB access helpers
│   │   ├── services/                Rules, reports, scoring, intelligence
│   │   ├── web/                     Flask dashboard
│   │   └── workers/                 Capture, detectors, and pipeline jobs
│   └── tests/                       Automated tests
├── frontend/
│   ├── desktop/                     Rule Editor and Rule/Report Viewer
│   └── web/                         Dashboard templates and static assets
├── scripts/launcher.py              Main service launcher
├── data/                            Ignored local runtime data
├── docs/                            Architecture and operating guides
├── .env.example                     Safe configuration template
├── .gitignore                       Secret and runtime-data protection
└── requirements.txt                 Pinned Python dependencies
```

Generated captures, parsed JSON, logs, rules, reports, STIX bundles, uploads, and local credentials belong under `data/`. They are intentionally ignored by Git.

## Prerequisites

On Ubuntu, install the required system packages:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip tshark nmap unzip
```

You also need a MongoDB Atlas cluster (or a reachable MongoDB deployment), an Atlas database user, and your current public IP added in Atlas **Network Access**.

## Quick start on Ubuntu

```bash
cd ~/Desktop
git clone https://github.com/rijaqazi/rijaqazi.git ThreatSentinel
cd ThreatSentinel

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

cp .env.example .env
nano .env
```

In `.env`, configure at least:

```dotenv
SECRET_KEY=replace-with-a-new-long-random-value
MONGODB_URI="mongodb+srv://DATABASE_USER:DATABASE_PASSWORD@YOUR_CLUSTER.mongodb.net/?retryWrites=true&w=majority"
TAXII_ADMIN_PASSWORD=replace-with-a-strong-password
TAXII_USER_PASSWORD=replace-with-a-strong-password
FILE_SERVER_USERNAME=choose-a-local-upload-username
FILE_SERVER_PASSWORD=choose-a-local-upload-password
```

Test Atlas before starting services:

```bash
python3 - <<'PY'
from pymongo import MongoClient
from backend.app.core.settings import settings

client = MongoClient(settings.mongodb_uri, serverSelectionTimeoutMS=5000)
client.admin.command("ping")
print("MongoDB connection OK")
PY
```

## Run the project

Activate the environment from the repository root in each new terminal:

```bash
cd ~/Desktop/ThreatSentinel
source .venv/bin/activate
```

For a 4 GB virtual machine, start only what you need:

```bash
# Dashboard: http://127.0.0.1:5000/
python3 scripts/launcher.py dashboard

# TAXII discovery: http://127.0.0.1:5002/taxii2/
python3 scripts/launcher.py taxii

# Secure upload service for the Rule Editor
python3 scripts/launcher.py upload
```

Start the normal local service set:

```bash
python3 scripts/launcher.py all
```

Start every service and background worker only when system memory permits:

```bash
python3 scripts/launcher.py all pipeline
```

Press `Ctrl+C` once in the launcher terminal to stop services it started. If a port is already in use, inspect existing processes instead of starting a duplicate:

```bash
sudo ss -ltnp | grep -E ':5000|:5001|:5002|:5005'
```

## Dashboard and desktop tools

Open the dashboard inside the Ubuntu machine:

```text
http://127.0.0.1:5000/
```

The login form requires all fields. Use first name `internal` for the central alerts, CVSS, and IOC view. The first name `infosecurity` opens the organization-specific view.

Open the desktop tools with the virtual environment active:

```bash
python3 frontend/desktop/rule_editor.py
python3 frontend/desktop/rule_report_viewer.py
```

## Safe local detector test

Use loopback or an isolated lab only. Example Nmap test:

```bash
# Terminal 1
sudo tshark -i any -a duration:20 -w /tmp/nmap-loopback-lab.pcapng

# Terminal 2, while capture is running
sudo nmap -sS -p 1-30 127.0.0.1

# Then process the capture
sudo cp /tmp/nmap-loopback-lab.pcapng data/captures/
sudo chown $USER:$USER data/captures/nmap-loopback-lab.pcapng
python3 -m backend.app.workers.capture.pcap_watch --once
python3 -m backend.app.workers.detectors.json_watch --detector nmap --once
```

Process detector results through the intelligence pipeline:

```bash
python3 -m backend.app.workers.alert_log_ingestion --once
python3 -m backend.app.workers.cvss_worker
python3 -m backend.app.workers.rule_worker
python3 -m backend.app.workers.ioc_worker --mode extract
python3 -m backend.app.workers.ioc_worker --mode stix
python3 -m backend.app.services.intelligence.stix_ingestion
```

The CVSS, rule, and IOC extract workers can continue monitoring. For a short demonstration, stop them with `Ctrl+C` after the first successful processing pass.

## Verify TAXII and tests

```bash
curl -i http://127.0.0.1:5002/taxii2/
python3 -m unittest discover -s backend/tests -p 'test_*.py'
python3 -m pip check
```

## Security rules

- Never commit `.env`, passwords, private keys, API tokens, captures, logs, or `data/credentials/`.
- Keep local services on `127.0.0.1` during development.
- Keep `DASHBOARD_COOKIE_SECURE=false` only for local HTTP. Use HTTPS and set it to `true` for an exposed deployment.
- Use strong, unique MongoDB, TAXII, dashboard, and file-upload passwords.
- Before committing, run `git status --short` and ensure runtime data has not been added.

## Documentation

- [Complete Project Guide](docs/ThreatSentinel_Project_Guide.docx) - detailed architecture, folder reference, installation, operation, testing, troubleshooting, and moving the project to a new Ubuntu laptop.
- [Architecture](docs/ARCHITECTURE.md)
- [Running instructions](docs/RUNNING.md)
- [Workflow command map](docs/WORKFLOWS.md)
- [Migration notes](docs/MIGRATION.md)
- [Security checklist](SECURITY_CHECKLIST.md)

## Moving to a new Ubuntu laptop

Use a fresh clone and create a fresh `.venv` and `.env`. Do not copy the old `.venv`, `.env`, or `data/credentials/`. MongoDB Atlas data remains in the cloud; add the new laptop public IP to Atlas Network Access and configure the new `.env` with valid credentials. The complete migration checklist is in the Project Guide above.
