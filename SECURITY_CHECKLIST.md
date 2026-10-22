# Security Release Checklist

Before sharing, demonstrating, or deploying this project, verify the following:

- [ ] The MongoDB Atlas credentials previously committed to source code have been revoked or rotated.
- [ ] `.env`, `creds.json`, certificates, and private keys are not tracked by Git.
- [ ] `.env` contains real local values; `.env.example` contains placeholders only.
- [ ] `python -m pip check` passes inside `.venv`.
- [ ] `python -m pip_audit -r requirements.txt` reports no known vulnerabilities.
- [ ] Flask development servers bind only to loopback; remote deployment uses a production WSGI server behind TLS.
- [ ] Authentication rate limiting and request-size limits are enabled.
- [ ] TAXII and upload service tests pass, including invalid payload and invalid ZIP rejection.

## Final review commands

```bash
grep -RInE --exclude-dir=.venv --exclude-dir=venv --include='*.py' 'password123|user123' .
grep -RIn --exclude-dir=.venv --exclude-dir=venv --include='*.py' 'mongodb+srv://' .
git ls-files .env data/credentials/upload_service.json
git log -S 'mongodb+srv://' --all -- '*.py'
```

The first three commands should produce no output. If the Git-history command finds the old connection string, do not treat it as safe merely because current files are clean: keep the associated database account revoked or rotate it, and coordinate any history rewrite before changing shared Git history.
