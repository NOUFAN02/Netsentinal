import os
import sqlite3

from flask import Flask, jsonify

try:
    from flask_cors import CORS
except ImportError:
    CORS = None

DEFAULT_DB = os.getenv("NETSENTINEL_DB", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "netsentinel.db")))


def create_app(db_path: str = None, test_config: dict = None) -> Flask:
    app = Flask(__name__)
    if test_config:
        app.config.update(test_config)

    app.config["DATABASE"] = db_path or os.getenv("NETSENTINEL_DB", DEFAULT_DB)

    if CORS is not None:
        CORS(app)
    else:
        @app.after_request
        def add_cors_headers(response):
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PUT, DELETE"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
            return response

    def q(sql, args=()):
        database = app.config.get("DATABASE", DEFAULT_DB)
        con = sqlite3.connect(database)
        con.row_factory = sqlite3.Row
        rows = [dict(row) for row in con.execute(sql, args).fetchall()]
        con.close()
        return rows

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.get("/api/incidents")
    def incidents():
        return jsonify(q("SELECT * FROM incidents ORDER BY end_time DESC LIMIT 200"))

    @app.get("/api/incidents/<int:iid>")
    def incident(iid):
        inc = q("SELECT * FROM incidents WHERE id = ?", (iid,))
        if not inc:
            return jsonify({"error": "not found"}), 404

        incident_data = inc[0]
        alerts = q(
            "SELECT * FROM alerts WHERE src_ip = ? AND dest_ip = ? ORDER BY timestamp",
            (incident_data["src_ip"], incident_data["dest_ip"]),
        )
        intel = {
            row["ip"]: row
            for row in q(
                "SELECT * FROM ip_intel WHERE ip IN (?, ?)",
                (incident_data["src_ip"], incident_data["dest_ip"]),
            )
        }

        return jsonify(
            {
                **incident_data,
                "alerts": alerts,
                "src_intel": intel.get(incident_data["src_ip"]),
                "dest_intel": intel.get(incident_data["dest_ip"]),
            }
        )

    @app.get("/api/stats/severity")
    def severity():
        return jsonify(q("SELECT severity, COUNT(*) AS c FROM alerts GROUP BY severity"))

    @app.get("/api/stats/top_attackers")
    def top_attackers():
        return jsonify(
            q(
                """
                SELECT CASE WHEN direction = 'to_server' THEN src_ip ELSE dest_ip END AS ip,
                       COUNT(*) AS c
                FROM alerts
                GROUP BY ip
                ORDER BY c DESC
                LIMIT 10
                """
            )
        )

    @app.get("/api/stats/protocols")
    def protocols():
        return jsonify(q("SELECT proto, COUNT(*) AS c FROM alerts GROUP BY proto"))

    return app


app = create_app()

if __name__ == "__main__":
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "True").lower() in ("true", "1")
    app.run(host=host, port=port, debug=debug)
