import os
import sqlite3
import tempfile
import unittest

from database.setup_db import setup_db


class TestDatabaseSetup(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_netsentinel.db")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_setup_db_creates_tables_and_indexes(self):
        result_path = setup_db(self.db_path)
        self.assertEqual(result_path, self.db_path)
        self.assertTrue(os.path.exists(self.db_path))

        con = sqlite3.connect(self.db_path)
        cur = con.cursor()

        tables = {
            row[0]
            for row in cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        self.assertIn("alerts", tables)
        self.assertIn("incidents", tables)
        self.assertIn("ip_intel", tables)
        self.assertIn("outbound_baseline", tables)

        indexes = {
            row[0]
            for row in cur.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
        }
        self.assertIn("idx_alerts_src", indexes)
        self.assertIn("idx_alerts_ts", indexes)

        con.close()

    def test_setup_db_is_idempotent(self):
        setup_db(self.db_path)
        # Calling again should not raise errors or duplicate tables
        setup_db(self.db_path)

        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("INSERT INTO ip_intel (ip, abuse_score) VALUES ('1.1.1.1', 0)")
        con.commit()

        # Third call preserves existing data
        setup_db(self.db_path)
        row = cur.execute("SELECT ip, abuse_score FROM ip_intel WHERE ip = '1.1.1.1'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "1.1.1.1")
        con.close()


if __name__ == "__main__":
    unittest.main()
