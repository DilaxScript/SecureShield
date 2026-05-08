#!/usr/bin/env bash

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$PROJECT_DIR"

if [[ ! -d venv ]]; then
  python3 -m venv venv
fi

source venv/bin/activate
unset PYTHONPATH

python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

cd "$PROJECT_DIR/frontend"
npm install
npm run build

cd "$PROJECT_DIR"
rm -rf secureshield/web/static/assets
cp -r frontend/dist/* secureshield/web/static/

exec uvicorn secureshield.web.api:app --host 0.0.0.0 --port 8000 --reload
