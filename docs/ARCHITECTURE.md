# Target Architecture

ThreatSentinel is being migrated from independent scripts into importable backend services. The migration is incremental: legacy commands remain as lightweight wrappers until a frontend replacement is ready.

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

| Legacy area | Backend owner | Status |
|---|---|---|
| `agent/heartbeat_server.py` | `api/v1/heartbeats.py` and heartbeat services | Wrapper retained |
| `ioc/taxi_server.py`, `pull_ioc.py`, `push_stix.py` | `integrations/taxii/` | Wrappers retained |
| `ioc/ioc_db.py` | STIX ingestion service and IOC repository | Wrapper retained |
| `ioc/extract.py`, `ioc/matching.py` | IOC pipeline service and worker | Wrappers retained |
| `cvss/cvss_automation.py` | CVSS service and worker | Wrapper retained |
| `Rule_Generation/rule_automation.py` | rule worker and policy service | Wrapper retained |
| `Rule_Generation` upload/report scripts | rules and reports services | Wrappers retained |
| `nmap/`, `arp/`, `icmp/` | detector workers | Compatibility commands retained |
| `new_detection/` capture scripts | capture workers and JSON watcher | Compatibility commands retained |
| detector alert logs | alert-log ingestion worker and normalized MongoDB alerts | Started by `pipeline` |

## UI boundary

`frontend/` is reserved for the replacement web UI. The Tkinter files `Rule_Generation/main.py` and `Rule_Generation/main2.py` remain legacy desktop interfaces and should not be treated as backend runtime services.

Runtime data is configured through `.env`; new runtime output should go under ignored `data/`. Historical generated files in legacy folders are intentionally retained until a separately approved cleanup step.
