# Workflow Commands

Use these commands as the canonical entry points.

| Workflow | Command |
|---|---|
| Local network services | `python3 scripts/launcher.py all` |
| Full threat-processing pipeline | `python3 scripts/launcher.py all pipeline` |
| Detector watchers and alert ingestion | `python3 scripts/launcher.py detector-nmap detector-arp detector-icmp alerts` |
| PCAP parser watcher | `python3 scripts/launcher.py capture` |
| Live protocol capture | `python3 -m backend.app.workers.capture.protocol_monitor --interface INTERFACE` |
| Parsed-JSON detector watcher | `python3 -m backend.app.workers.detectors.json_watch --once` |
| CVSS worker | `python3 -m backend.app.workers.cvss_worker` |
| Rule generation | `python3 -m backend.app.workers.rule_worker monitor` |
| PDF report generation | `python3 -m backend.app.services.reports.pdf_generator --hours 24 --ipinfo TOKEN` |
| IOC extraction | `python3 -m backend.app.workers.ioc_worker --mode extract` |
| STIX generation | `python3 -m backend.app.workers.ioc_worker --mode stix` |
| STIX ingestion into MongoDB | `python3 -m backend.app.services.intelligence.stix_ingestion` |
| Desktop rule editor | `python3 frontend/desktop/rule_editor.py` |
| Desktop rule/report viewer | `python3 frontend/desktop/rule_report_viewer.py` |

## Desktop rule interfaces

`frontend/desktop/rule_editor.py` edits a generated rule, creates a ZIP, and uploads it through the local authenticated service. `frontend/desktop/rule_report_viewer.py` provides the secondary rule/report viewer. They are not started by the launcher.

Generated PCAPs, parsed data, logs, downloaded archives, and detector output belong under `data/` and remain ignored by Git.
