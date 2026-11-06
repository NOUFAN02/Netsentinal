import subprocess
import sys
import time

cycle = 0

try:
    print("NetSentinel background pipeline starting... Press Ctrl+C to stop.")
    while True:
        subprocess.run([sys.executable, "parser/alert_parser.py"], check=False)
        subprocess.run([sys.executable, "correlator/correlate_alerts.py"], check=False)
        if cycle % 6 == 0:
            subprocess.run([sys.executable, "enrich_ips.py"], check=False)
        cycle += 1
        time.sleep(10)
except KeyboardInterrupt:
    print("\nNetSentinel pipeline stopped cleanly.")
