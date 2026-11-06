import json
import os
import sqlite3
import tempfile
import unittest

from api.app import create_app
from database.setup_db import setup_db


class TestAPI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_api.db")
        setup_db(self.db_path)

        # Seed data
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute(
            """
            INSERT INTO alerts (timestamp, src_ip, src_port, dest_ip, dest_port, proto, signature, signature_id, category, severity, direction, count)
            VALUES ('2026-11-06T10:00:00Z', '192.168.1.10', 4444, '192.168.1.20', 80, 'TCP', 'Port Scan', 1001, 'Scan', 'High', 'to_server', 5)
            """
        )
        cur.execute(
            """
            INSERT INTO incidents (id, src_ip, dest_ip, start_time, end_time, alert_count, risk, status)
            VALUES (1, '192.168.1.10', '192.168.1.20', '2026-11-06T10:00:00Z', '2026-11-06T10:01:00Z', 5, 'High', 'open')
            """
        )
        cur.execute(
            """
            INSERT INTO ip_intel (ip, abuse_score, country, isp, last_checked)
            VALUES ('192.168.1.10', 85, 'US', 'Example ISP', '2026-11-06T10:00:00Z')
            """
        )
        con.commit()
        con.close()

        self.app = create_app(db_path=self.db_path, test_config={"TESTING": True})
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_health(self):
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json(), {"status": "ok"})

    def test_get_incidents(self):
        res = self.client.get("/api/incidents")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["src_ip"], "192.168.1.10")

    def test_get_incident_detail(self):
        res = self.client.get("/api/incidents/1")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["id"], 1)
        self.assertIn("alerts", data)
        self.assertEqual(len(data["alerts"]), 1)
        self.assertIsNotNone(data["src_intel"])
        self.assertEqual(data["src_intel"]["abuse_score"], 85)

    def test_get_incident_not_found(self):
        res = self.client.get("/api/incidents/999")
        self.assertEqual(res.status_code, 404)

    def test_stats_severity(self):
        res = self.client.get("/api/stats/severity")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(any(row["severity"] == "High" for row in data))

    def test_stats_top_attackers(self):
        res = self.client.get("/api/stats/top_attackers")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["ip"], "192.168.1.10")

    def test_stats_protocols(self):
        res = self.client.get("/api/stats/protocols")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(any(row["proto"] == "TCP" for row in data))


if __name__ == "__main__":
    unittest.main()
