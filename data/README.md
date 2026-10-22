# Local runtime data

This folder is intentionally ignored by Git. ThreatSentinel creates its working
data here at runtime:

- `captures/` and `parsed/` — captured PCAPs and tshark JSON exports
- `detector_output/` — detector logs and normalized alert files
- `iocs/` and `stix/` — extracted IOCs and generated STIX bundles
- `rules/`, `reports/`, `rule_exports/`, and `uploads/` — generated rule artifacts
- `credentials/upload_service.json` — local secure-upload credentials

Do not commit real captures, alerts, reports, archives, credentials, or `.env`.
