# Workflow Commands

Use these commands as the canonical entry points. The older filenames remain as compatibility wrappers so existing commands continue to work.

| Workflow | Canonical command | Compatibility command |
|---|---|---|
| Local network services | `python3 scripts/launcher.py all` | `python3 agent/run.py` |
| Full threat-processing pipeline | `python3 scripts/launcher.py all pipeline` | — |
| Detector watchers and alert ingestion | `python3 scripts/launcher.py detector-nmap detector-arp detector-icmp alerts` | `python3 new_detection/new2.py --detector NAME` |
| PCAP parser watcher | `python3 scripts/launcher.py capture` | `python3 new_detection/auto_parse.py` |
| Live protocol capture | `python3 -m backend.app.workers.capture.protocol_monitor --interface INTERFACE` | `python3 new_detection/monitor_tshark_trigger.py --interface INTERFACE` |
| Parsed-JSON detector watcher | `python3 -m backend.app.workers.detectors.json_watch --once` | `python3 new_detection/new2.py --once` |
| CVSS worker | `python3 cvss/cvss_automation.py` | same command |
| Rule generation | `python3 Rule_Generation/rule_automation.py monitor` | same command |
| IOC extraction | `python3 -m backend.app.workers.ioc_worker --mode extract` | `python3 ioc/extract.py` |
| STIX generation | `python3 -m backend.app.workers.ioc_worker --mode stix` | `python3 ioc/matching.py` |
| STIX ingestion into MongoDB | `python3 -m backend.app.services.intelligence.stix_ingestion` | `python3 ioc/ioc_db.py` |

## Desktop interfaces retained during migration

`Rule_Generation/main.py` and `Rule_Generation/main2.py` are older Tkinter desktop rule-management interfaces. They are not started by the launcher and are not backend services. Keep them as reference/compatibility tools until their UI is rebuilt under `frontend/` against the backend API.

Generated PCAPs, parsed data, logs, downloaded archives, and detector output belong under `data/` and remain ignored by Git. Existing historical files in the legacy folders are retained.
