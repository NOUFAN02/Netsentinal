import datetime
import os
import sqlite3

DEFAULT_DB = os.getenv("NETSENTINEL_DB", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "netsentinel.db")))
WINDOW = 60
INFO_CATS = {"Generic Protocol Command Decode"}


def risk_from(alert_count: int, max_sev: str, has_non_info: bool) -> str:
    if max_sev == "High" and has_non_info and alert_count >= 5:
        return "High"
    if max_sev == "High":
        return "High"
    if max_sev == "Medium":
        return "Medium"
    return "Low"


def correlate(db_path: str = None, window_seconds: int = WINDOW) -> int:
    database = db_path or DEFAULT_DB
    con = sqlite3.connect(database)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    rows = cur.execute(
        """
        SELECT * FROM alerts
        WHERE timestamp > COALESCE(
            (SELECT MAX(end_time) FROM incidents i
             WHERE i.src_ip = alerts.src_ip AND i.dest_ip = alerts.dest_ip),
            '1970-01-01'
        )
        ORDER BY timestamp
        """
    ).fetchall()

    processed_count = 0
    for row in rows:
        ts = datetime.datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
        incident = cur.execute(
            """
            SELECT * FROM incidents
            WHERE src_ip = ? AND dest_ip = ? AND status = 'open'
            ORDER BY end_time DESC LIMIT 1
            """,
            (row["src_ip"], row["dest_ip"]),
        ).fetchone()

        if incident:
            end = datetime.datetime.fromisoformat(incident["end_time"].replace("Z", "+00:00"))
            if (ts - end).total_seconds() <= window_seconds:
                new_count = incident["alert_count"] + row["count"]
                has_non_info = row["category"] not in INFO_CATS or incident["risk"] in ("High", "Medium")
                risk = risk_from(new_count, row["severity"], has_non_info)
                cur.execute(
                    "UPDATE incidents SET end_time = ?, alert_count = ?, risk = ? WHERE id = ?",
                    (row["timestamp"], new_count, risk, incident["id"]),
                )
                processed_count += 1
                continue

        has_non_info = row["category"] not in INFO_CATS
        risk = risk_from(row["count"], row["severity"], has_non_info)
        cur.execute(
            """
            INSERT INTO incidents (src_ip, dest_ip, start_time, end_time, alert_count, risk)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                row["src_ip"],
                row["dest_ip"],
                row["timestamp"],
                row["timestamp"],
                row["count"],
                risk,
            ),
        )
        processed_count += 1

    con.commit()
    con.close()
    return processed_count


if __name__ == "__main__":
    count = correlate()
    print(f"Correlated {count} alert(s)")
