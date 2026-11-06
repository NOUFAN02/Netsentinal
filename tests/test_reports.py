import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from database.setup_db import setup_db
from reports.generate_report import build_report, export_csv, export_json, fetch_incidents


class TestReports(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_rep.db")
        self.output_dir = Path(self.temp_dir.name) / "output"
        setup_db(self.db_path)

        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute(
            """
            INSERT INTO incidents (id, src_ip, dest_ip, start_time, end_time, alert_count, risk, status)
            VALUES (1, '10.0.0.5', '10.0.0.10', '2026-11-06T12:00:00Z', '2026-11-06T12:05:00Z', 12, 'High', 'open')
            """
        )
        con.commit()
        con.close()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_fetch_incidents(self):
        rows = fetch_incidents(db_path=self.db_path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["src_ip"], "10.0.0.5")

    def test_export_csv(self):
        rows = fetch_incidents(db_path=self.db_path)
        csv_file = self.output_dir / "test.csv"
        export_csv(rows, csv_file)
        self.assertTrue(csv_file.exists())
        content = csv_file.read_text(encoding="utf-8")
        self.assertIn("10.0.0.5", content)
        self.assertIn("High", content)

    def test_export_json(self):
        rows = fetch_incidents(db_path=self.db_path)
        json_file = self.output_dir / "test.json"
        export_json(rows, json_file)
        self.assertTrue(json_file.exists())
        data = json.loads(json_file.read_text(encoding="utf-8"))
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["src_ip"], "10.0.0.5")

    def test_build_report(self):
        result = build_report(db_path=self.db_path, output_dir=self.output_dir)
        self.assertIn("csv", result)
        self.assertIn("json", result)
        self.assertTrue(Path(result["csv"]).exists())
        self.assertTrue(Path(result["json"]).exists())


if __name__ == "__main__":
    unittest.main()

