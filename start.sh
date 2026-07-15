#!/usr/bin/env bash
# SVP — start API + frontend dev servers
set -euo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)

# Kill any stale instances
pkill -f "uvicorn api.main" 2>/dev/null || true
pkill -f "vite" 2>/dev/null || true
sleep 1

echo "Starting SVP..."
echo "  API  → http://localhost:8000"
echo "  Web  → http://localhost:5173"
echo ""

source "$ROOT/venv/bin/activate"
cd "$ROOT" && uvicorn api.main:app --reload --port 8000 &
API_PID=$!

cd "$ROOT/web" && npm run dev -- --port 5173 &
WEB_PID=$!

trap "kill $API_PID $WEB_PID 2>/dev/null" EXIT INT TERM
wait
