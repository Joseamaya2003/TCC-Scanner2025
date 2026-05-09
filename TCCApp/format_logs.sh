#!/bin/bash
set -e 
DATE=$(date +"%Y-%m-%d")
LOG_PATH=$(ls -1t /shared/lynis-*.log 2>/dev/null | head -n 1)

echo "[INFO] Checking for log file..."

if [[ -z "$LOG_PATH" ]]; then
    echo "[ERROR] Log file not found at $LOG_PATH"
    ls -l /shared
    exit 1
fi

echo "[INFO] running HTML formatter..."
python3 /HTML.py 

cd /shared
mv lynis_security_report.html reports/lynis_security_report_${DATE}.html
cd reports/

echo "[INFO] Starting HTTP server on port 8080"

python3 -m http.server 8080