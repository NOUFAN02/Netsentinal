#!/usr/bin/env bash
set -e

for pid in $(pgrep -af "python run_pipeline.py|python api/app.py|http.server 8080 --directory dashboard" | awk '{print $1}'); do
  kill "$pid" 2>/dev/null || true
done

sudo systemctl stop suricata 2>/dev/null || true

echo "NetSentinel stopped"
