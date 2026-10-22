# Release migration notes

The former top-level script folders were consolidated into `backend/`,
`frontend/desktop/`, and `data/`.

Before updating an older local checkout, preserve its generated runtime data:

```bash
cd ~/Desktop/ThreatSentinel
install -d -m 700 data/credentials
mkdir -p data/rules data/reports data/uploads data/stix
test -f Rule_Generation/creds.json && cp -p Rule_Generation/creds.json data/credentials/upload_service.json
test -d Rule_Generation/rules_repository && cp -a Rule_Generation/rules_repository/. data/rules/
test -d Rule_Generation/reports && cp -a Rule_Generation/reports/. data/reports/
test -d Rule_Generation/uploads && cp -a Rule_Generation/uploads/. data/uploads/
test -d ioc/stix_output && cp -a ioc/stix_output/. data/stix/

# Update any old explicit runtime paths in .env.
sed -i 's#^TAXII_BUNDLES_DIR=.*#TAXII_BUNDLES_DIR=./data/stix#' .env
sed -i 's#^REPORTS_OUTPUT_DIR=.*#REPORTS_OUTPUT_DIR=./data/reports#' .env
```

Then update the project. New commands are listed in `RUNNING.md` and
`WORKFLOWS.md`.
