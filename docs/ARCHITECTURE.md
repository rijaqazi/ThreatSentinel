# Target Architecture

ThreatSentinel is organized around importable backend services and a small set of operational scripts. Runtime output is isolated under `data/` and is ignored by Git.

```text
backend/app/
├── api/v1/             HTTP endpoints
├── core/               settings and security boundaries
├── integrations/taxii/ TAXII server and clients
├── repositories/       MongoDB access
├── services/           scoring, intelligence, rules, reports
└── workers/            capture, detection, and processing jobs
```

## Current ownership

| Capability | Backend owner | Entry point |
|---|---|---|
| Heartbeats | `api/v1/heartbeats.py` and alert services | `python3 -m backend.app.api.v1.heartbeats` |
| TAXII | `integrations/taxii/` | `python3 -m backend.app.integrations.taxii.server` |
| IOC extraction and STIX | intelligence services and workers | `python3 -m backend.app.workers.ioc_worker` |
| CVSS scoring | scoring service and worker | `python3 -m backend.app.workers.cvss_worker` |
| Rule generation and uploads | rules services and worker | `python3 -m backend.app.workers.rule_worker` |
| Nmap, ARP, and ICMP detection | detector workers | `python3 -m backend.app.workers.detectors.json_watch` |
| PCAP parsing and live capture | capture workers | `python3 -m backend.app.workers.capture.pcap_watch` |
| detector alert logs | alert-log ingestion worker and normalized MongoDB alerts | Started by `pipeline` |

## UI boundary

`frontend/desktop/` contains the current Tkinter rule-management interfaces. They consume generated rules and reports from `data/`; they are not backend runtime services.

Runtime data is configured through `.env`; all generated output belongs under ignored `data/`.
