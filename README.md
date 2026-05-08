# SecureShield

Local-a run panna:

```bash
chmod +x run_local.sh
./run_local.sh
```

App `http://localhost:8000` la open pannalaam.

Notes:

- Default database ippo local SQLite file: `secureshield.db`
- Docker thevai illa
- Scanner features use panna host machine-la `docker` and `trivy` installed irukkanum
- First Trivy scan internet use panni vulnerability DB download pannum. DB ready aana apram `TRIVY_OFFLINE_SCAN=1 TRIVY_SKIP_DB_UPDATE=1` set panni offline scan pannalaam.
- Web admin auto-create venumna `.env` la `DEFAULT_ADMIN_PASSWORD` and `APP_SECRET_KEY` set pannunga.
- `secureshield serve` run panna munnaadi built frontend static files auto-sync aagum
- Manual sync venumna:

```bash
/home/dilax/secureshield/venv/bin/secureshield sync-ui
```
