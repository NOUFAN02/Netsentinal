#!/usr/bin/env bash
set -e

sudo systemctl start suricata 2>/dev/null || true
source venv/bin/activate 2>/dev/null || true

nohup python run_pipeline.py > logs/pipeline.log 2>&1 &
nohup python api/app.py > logs/api.log 2>&1 &
nohup python -m http.server 8080 --directory dashboard > logs/dash.log 2>&1 &

echo "NetSentinel is running"
