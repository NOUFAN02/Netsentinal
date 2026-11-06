import json
import os
import sqlite3
import tempfile
import unittest

from database.setup_db import setup_db
from parser.alert_parser import parse, read_offset, write_offset


class TestAlertParser(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test.db")
        self.state_path = os.path.join(self.temp_dir.name, "test.state")
        self.eve_path = os.path.join(self.temp_dir.name, "eve.json")
        setup_db(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_offset_read_write(self):
        self.assertEqual(read_offset(self.state_path), 0)
        write_offset(1024, self.state_path)
        self.assertEqual(read_offset(self.state_path), 1024)

    def test_missing_eve_file_raises_error(self):
        non_existent = os.path.join(self.temp_dir.name, "missing.json")
        with self.assertRaises(FileNotFoundError):
            parse(eve_file=non_existent, db_path=self.db_path, state_file=self.state_path)

    def test_parse_alerts_and_deduplication(self):
        records = [
            # Event 1: Valid Alert
            {
                "timestamp": "2026-11-06T10:00:00.000000+0000",
                "event_type": "alert",
                "src_ip": "192.168.1.100",
                "src_port": 4444,
                "dest_ip": "192.168.1.50",
                "dest_port": 80,
                "proto": "TCP",
                "direction": "to_server",
                "alert": {
                    "signature": "ET SCAN Nmap Scripting Engine User-Agent",
                    "signature_id": 2009582,
                    "category": "Attempted Information Leak",
                    "severity": 1,
                },
            },
            # Event 2: Flow event (should be ignored)
            {
                "timestamp": "2026-11-06T10:00:01.000000+0000",
                "event_type": "flow",
                "src_ip": "192.168.1.100",
                "dest_ip": "192.168.1.50",
            },
            # Event 3: Duplicate of Event 1 (should trigger count increment)
            {
                "timestamp": "2026-11-06T10:00:00.000000+0000",
                "event_type": "alert",
                "src_ip": "192.168.1.100",
                "src_port": 4444,
                "dest_ip": "192.168.1.50",
                "dest_port": 80,
                "proto": "TCP",
                "direction": "to_server",
                "alert": {
                    "signature": "ET SCAN Nmap Scripting Engine User-Agent",
                    "signature_id": 2009582,
                    "category": "Attempted Information Leak",
                    "severity": 1,
                },
            },
        ]

        with open(self.eve_path, "w", encoding="utf-8") as f:
            for rec in records:
                f.write(json.dumps(rec) + "\n")

        count = parse(eve_file=self.eve_path, db_path=self.db_path, state_file=self.state_path)
        self.assertEqual(count, 2)  # 2 alert events processed

        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        rows = cur.execute("SELECT src_ip, dest_ip, severity, count FROM alerts").fetchall()
        con.close()

        self.assertEqual(len(rows), 1)  # deduplicated by unique constraint
        self.assertEqual(rows[0][0], "192.168.1.100")
        self.assertEqual(rows[0][1], "192.168.1.50")
        self.assertEqual(rows[0][2], "High")
        self.assertEqual(rows[0][3], 2)  # count incremented to 2

        # Verify offset moved
        self.assertGreater(read_offset(self.state_path), 0)


if __name__ == "__main__":
    unittest.main()
