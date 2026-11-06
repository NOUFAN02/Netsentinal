import os
import sqlite3

DEFAULT_DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "netsentinel.db"))
DB_PATH = os.getenv("NETSENTINEL_DB", DEFAULT_DB_PATH)

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    src_ip TEXT,
    src_port INTEGER,
    dest_ip TEXT,
    dest_port INTEGER,
    proto TEXT,
    signature TEXT,
    signature_id INTEGER,
    category TEXT,
    severity TEXT,
    direction TEXT,
    raw_json TEXT,
    count INTEGER DEFAULT 1,
    UNIQUE(timestamp, src_ip, dest_ip, signature_id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT,
    dest_ip TEXT,
    start_time TEXT,
    end_time TEXT,
    alert_count INTEGER,
    risk TEXT,
    status TEXT DEFAULT 'open',
    UNIQUE(src_ip, dest_ip, start_time)
);

CREATE TABLE IF NOT EXISTS ip_intel (
    ip TEXT PRIMARY KEY,
    abuse_score INTEGER,
    country TEXT,
    isp TEXT,
    last_checked TEXT,
    raw_json TEXT
);

CREATE TABLE IF NOT EXISTS outbound_baseline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    internal_ip TEXT,
    dest_ip TEXT,
    dest_port INTEGER,
    first_seen TEXT,
    last_seen TEXT,
    hit_count INTEGER DEFAULT 0,
    avg_interval REAL DEFAULT 0,
    UNIQUE(internal_ip, dest_ip, dest_port)
);
"""


def setup_db(db_path: str = None) -> str:
    target_path = db_path or os.getenv("NETSENTINEL_DB", DEFAULT_DB_PATH)
    parent_dir = os.path.dirname(os.path.abspath(target_path))
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)
    con = sqlite3.connect(target_path)
    con.executescript(SCHEMA)
    con.commit()
    con.close()
    return target_path


if __name__ == "__main__":
    ready_path = setup_db()
    print(f"Database ready at {ready_path}")
