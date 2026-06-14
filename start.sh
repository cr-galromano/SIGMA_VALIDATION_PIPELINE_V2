#!/usr/bin/env bash
# SVP — start API + frontend dev servers
set -euo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)

echo "Starting SVP..."
echo "  API  → http://localhost:8000"
echo "  Web  → http://localhost:5173"
echo ""

# API (background)
source "$ROOT/venv/bin/activate"
uvicorn api.main:app --reload --port 8000 --app-dir "$ROOT" &
API_PID=$!

# Frontend
cd "$ROOT/web" && npm run dev &
WEB_PID=$!

trap "kill $API_PID $WEB_PID 2>/dev/null" EXIT INT TERM
wait
