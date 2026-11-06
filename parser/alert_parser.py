import json
import os
import sqlite3

DEFAULT_EVE = os.getenv("SURICATA_EVE_PATH", "/var/log/suricata/eve.json")
DEFAULT_STATE = os.getenv("NETSENTINEL_STATE", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".parser_state")))
DEFAULT_DB = os.getenv("NETSENTINEL_DB", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "netsentinel.db")))

SEV_MAP = {1: "High", 2: "Medium", 3: "Low"}


def read_offset(state_path: str = None) -> int:
    path = state_path or DEFAULT_STATE
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                value = f.read().strip()
                return int(value or 0)
        except (ValueError, OSError):
            return 0
    return 0


def write_offset(offset: int, state_path: str = None) -> None:
    path = state_path or DEFAULT_STATE
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(str(offset))


def parse(eve_file: str = None, db_path: str = None, state_file: str = None) -> int:
    eve_path = eve_file or DEFAULT_EVE
    database = db_path or DEFAULT_DB
    state_path = state_file or DEFAULT_STATE

    if not os.path.exists(eve_path):
        raise FileNotFoundError(f"Suricata eve.json not found at {eve_path}")

    offset = read_offset(state_path)
    con = sqlite3.connect(database)
    cur = con.cursor()
    parsed_count = 0

    with open(eve_path, "r", encoding="utf-8") as f:
        f.seek(offset)
        for line in f:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "alert":
                continue

            alert = event.get("alert", {})
            cur.execute(
                """
                INSERT INTO alerts (
                    timestamp, src_ip, src_port, dest_ip, dest_port,
                    proto, signature, signature_id, category, severity,
                    direction, raw_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(timestamp, src_ip, dest_ip, signature_id)
                DO UPDATE SET count = count + 1
                """,
                (
                    event.get("timestamp"),
                    event.get("src_ip"),
                    event.get("src_port"),
                    event.get("dest_ip"),
                    event.get("dest_port"),
                    event.get("proto"),
                    alert.get("signature"),
                    alert.get("signature_id"),
                    alert.get("category"),
                    SEV_MAP.get(alert.get("severity"), "Low"),
                    event.get("direction"),
                    line.strip(),
                ),
            )
            parsed_count += 1

        write_offset(f.tell(), state_path)

    con.commit()
    con.close()
    return parsed_count


if __name__ == "__main__":
    count = parse()
    print(f"Parsed {count} new alert(s)")
