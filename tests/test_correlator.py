import os
import sqlite3
import tempfile
import unittest

from correlator.correlate_alerts import correlate, risk_from
from database.setup_db import setup_db


class TestCorrelator(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test.db")
        setup_db(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_risk_from(self):
        self.assertEqual(risk_from(10, "High", True), "High")
        self.assertEqual(risk_from(1, "High", False), "High")
        self.assertEqual(risk_from(3, "Medium", True), "Medium")
        self.assertEqual(risk_from(10, "Low", True), "Low")

    def test_correlation_within_window(self):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        # Insert two alerts 30 seconds apart (within 60s window)
        cur.execute(
            """
            INSERT INTO alerts (timestamp, src_ip, src_port, dest_ip, dest_port, proto, signature, signature_id, category, severity, direction, count)
            VALUES ('2026-11-06T10:00:00Z', '10.0.0.1', 1234, '10.0.0.2', 80, 'TCP', 'Sig 1', 101, 'Bad Web', 'High', 'to_server', 2)
            """
        )
        cur.execute(
            """
            INSERT INTO alerts (timestamp, src_ip, src_port, dest_ip, dest_port, proto, signature, signature_id, category, severity, direction, count)
            VALUES ('2026-11-06T10:00:30Z', '10.0.0.1', 1235, '10.0.0.2', 80, 'TCP', 'Sig 2', 102, 'Bad Web', 'High', 'to_server', 3)
            """
        )
        con.commit()
        con.close()

        count = correlate(self.db_path)
        self.assertEqual(count, 2)

        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        incidents = cur.execute("SELECT * FROM incidents").fetchall()
        con.close()

        # Both alerts should be merged into single incident
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        # alert_count = 2 + 3 = 5
        self.assertEqual(inc[5], 5)
        self.assertEqual(inc[6], "High")

    def test_correlation_outside_window(self):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        # Insert two alerts 120 seconds apart (> 60s window)
        cur.execute(
            """
            INSERT INTO alerts (timestamp, src_ip, src_port, dest_ip, dest_port, proto, signature, signature_id, category, severity, direction, count)
            VALUES ('2026-11-06T10:00:00Z', '10.0.0.1', 1234, '10.0.0.2', 80, 'TCP', 'Sig 1', 101, 'Bad Web', 'Low', 'to_server', 1)
            """
        )
        cur.execute(
            """
            INSERT INTO alerts (timestamp, src_ip, src_port, dest_ip, dest_port, proto, signature, signature_id, category, severity, direction, count)
            VALUES ('2026-11-06T10:02:00Z', '10.0.0.1', 1235, '10.0.0.2', 80, 'TCP', 'Sig 2', 102, 'Bad Web', 'Low', 'to_server', 1)
            """
        )
        con.commit()
        con.close()

        correlate(self.db_path)

        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        incidents = cur.execute("SELECT * FROM incidents").fetchall()
        con.close()

        # Two separate incidents
        self.assertEqual(len(incidents), 2)


if __name__ == "__main__":
    unittest.main()

