# SecureShield

SecureShield is a local container security scanning platform with a React dashboard, FastAPI backend, and CLI. It scans container images and local source paths, stores scan history in SQLite by default, and provides reports for vulnerability review and remediation workflows.

## Features

- Container image vulnerability scanning through Trivy
- CIS-style container hardening checks
- Runtime security checks for container configuration risks
- Supply-chain checks for mutable tags, provenance gaps, and risky startup patterns
- Local secret detection for source folders
- Web dashboard with scan history, reports, admin users, scheduled jobs, and export views
- CLI commands for scans, history, reports, and serving the web app
- Optional Gemini-powered AI remediation and chat assistance
- SQLite by default, with database configuration available through environment variables

## Tech Stack

- Backend: Python, FastAPI, SQLAlchemy, Uvicorn
- Frontend: React, Vite, CSS
- Scanner: Trivy plus local SecureShield scanner modules
- CLI: Click
- Database: SQLite by default
- Optional services: Redis cache, Gemini API

## Project Structure

```text
secureshield/
  web/api.py              FastAPI application and API routes
  scanner/                CVE, CIS, runtime, supply-chain, and secrets scanners
  ai/                     Optional AI remediation service
  models.py               SQLAlchemy models
  db.py                   Database setup and migrations
  repository.py           Persistence helpers
  cli.py                  secureshield CLI commands
  web/static/             Built frontend served by the API

frontend/
  src/                    React dashboard source
  public/                 Public frontend assets
  package.json            Frontend scripts and dependencies

run_local.sh              One-command local setup and server start
requirements.txt          Python runtime dependencies
setup.py                  Python package and CLI entry point
Dockerfile                Container build
docker-compose.yml        Compose setup
.env.example              Example environment configuration
```

## Requirements

- Python 3.11 or newer
- Node.js and npm
- Docker, if scanning local Docker images or containers
- Trivy, if using vulnerability scanning

Install Trivy before running real vulnerability scans. The first Trivy scan may download the vulnerability database from the internet.

## Quick Start

```bash
cd /home/dilax/secureshield
chmod +x run_local.sh
./run_local.sh
```

Then open:

```text
http://localhost:8000
```

The script creates a virtual environment, installs Python dependencies, installs the package, installs frontend dependencies, builds the React UI, syncs it into `secureshield/web/static`, and starts Uvicorn.

## Environment Setup

Create a local `.env` from the example:

```bash
cp .env.example .env
```

Important values:

```env
DB_CONNECTION=sqlite
DB_DATABASE=secureshield.db

APP_SECRET_KEY=change-me-to-a-long-random-value
DEFAULT_ADMIN_USERNAME=admin
DEFAULT_ADMIN_PASSWORD=change-me-before-use

GEMINI_API_KEY=
GEMINI_MODEL=gemini-flash-latest

TRIVY_OFFLINE_SCAN=0
TRIVY_SKIP_DB_UPDATE=0
```

Set `DEFAULT_ADMIN_PASSWORD` to auto-create an admin user at startup. Set `GEMINI_API_KEY` only if you want AI remediation and chat features.

## CLI Usage

After installing the package with `pip install -e .`, use:

```bash
secureshield --help
```

Run a full scan:

```bash
secureshield scan nginx:latest
```

Export scan output:

```bash
secureshield scan nginx:latest --format json --output scan.json
secureshield scan nginx:latest --format csv --output findings.csv
```

Run individual scanners:

```bash
secureshield cis-check nginx:latest
secureshield runtime-check nginx:latest
secureshield supply-chain-check nginx:latest
secureshield secrets-scan /path/to/source
```

View history and export reports:

```bash
secureshield history --limit 10
secureshield report-export --format md --output report.md
secureshield report-export --format json --output report.json
```

Build and sync frontend assets:

```bash
secureshield build-ui
secureshield sync-ui
```

Run the web server through the CLI:

```bash
secureshield serve --host 0.0.0.0 --port 8000 --reload
```

## API Endpoints

Main routes include:

- `GET /api/health`
- `GET /api/scan/{image}`
- `GET /api/critical/{image}`
- `GET /api/cis/{image}`
- `GET /api/runtime/{target}`
- `GET /api/supply-chain/{image}`
- `GET /api/secrets?path=/path/to/source`
- `GET /api/history`
- `GET /api/history/{record_id}`
- `GET /api/reports/summary`
- `GET /api/reports/export`
- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `POST /api/jobs/scan`
- `GET /api/jobs`
- `POST /api/ai/remediate`
- `POST /api/ai/chat`
- `WS /ws/scan`

## Frontend Development

Run the Vite dev server:

```bash
cd frontend
npm install
npm run dev
```

Default frontend URL:

```text
http://localhost:5173
```

The Vite dev server proxies `/api` requests to `http://localhost:8000`.

Build the frontend:

```bash
cd frontend
npm run build
```

Sync the build into the backend static directory:

```bash
cd /home/dilax/secureshield
secureshield sync-ui
```

## Trivy Offline Mode

For the first scan, let Trivy download its vulnerability database. After the DB is available locally, offline mode can be enabled:

```bash
TRIVY_OFFLINE_SCAN=1 TRIVY_SKIP_DB_UPDATE=1 secureshield scan nginx:latest
```

You can also set these values in `.env`.

## Docker

Build and run with Docker if needed:

```bash
docker build -t secureshield .
docker run --rm -p 8000:8000 secureshield
```

Or use Compose:

```bash
docker compose up --build
```

## GitHub Notes

Do not commit local runtime files or secrets. The `.gitignore` already excludes:

```text
.env
venv/
frontend/node_modules/
frontend/dist/
secureshield.db
__pycache__/
*.pyc
.cache/
.pytest_cache/
```

First-time GitHub push:

```bash
cd /home/dilax/secureshield
git init
git add .
git commit -m "Initial SecureShield project"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/secureshield.git
git push -u origin main
```

## Notes

- This project is intended for local security testing and demonstration workflows.
- Scanner accuracy depends on installed tools, local Docker access, and vulnerability database freshness.
- AI features are optional and disabled unless `GEMINI_API_KEY` is configured.
