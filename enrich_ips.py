import datetime
import ipaddress
import os
import sqlite3

import requests
from dotenv import load_dotenv

load_dotenv()

DEFAULT_KEY = os.getenv("ABUSEIPDB_API_KEY")
DEFAULT_DB = os.getenv("NETSENTINEL_DB", os.path.abspath(os.path.join(os.path.dirname(__file__), "netsentinel.db")))


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


def enrich(db_path: str = None, api_key: str = None) -> int:
    database = db_path or DEFAULT_DB
    key = api_key if api_key is not None else DEFAULT_KEY

    con = sqlite3.connect(database)
    cur = con.cursor()

    ips = {row[0] for row in cur.execute("SELECT DISTINCT src_ip FROM alerts WHERE src_ip IS NOT NULL")}
    ips |= {row[0] for row in cur.execute("SELECT DISTINCT dest_ip FROM alerts WHERE dest_ip IS NOT NULL")}

    enriched_count = 0
    for ip in sorted(ips):
        if not ip or is_private(ip):
            continue
        if cur.execute("SELECT 1 FROM ip_intel WHERE ip = ?", (ip,)).fetchone():
            continue

        if not key:
            continue

        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=15,
            )
            if response.status_code == 200:
                data = response.json().get("data", {})
                cur.execute(
                    """
                    INSERT OR REPLACE INTO ip_intel
                    (ip, abuse_score, country, isp, last_checked, raw_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ip,
                        data.get("abuseConfidenceScore"),
                        data.get("countryCode"),
                        data.get("isp"),
                        datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        response.text,
                    ),
                )
                enriched_count += 1
        except requests.RequestException:
            continue

    con.commit()
    con.close()
    return enriched_count


if __name__ == "__main__":
    count = enrich()
    print(f"Enriched {count} external IP(s)")
