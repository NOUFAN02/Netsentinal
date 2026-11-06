import csv
import json
import os
import sqlite3
from pathlib import Path

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

DEFAULT_DB = os.getenv("NETSENTINEL_DB", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "netsentinel.db")))
REPORT_DIR = Path(os.getenv("NETSENTINEL_REPORT_DIR", Path(__file__).resolve().parent / "output"))
REPORT_DIR.mkdir(exist_ok=True, parents=True)


def fetch_incidents(mode: str = "recent", n: int = 20, incident_id: int = None, db_path: str = None) -> list:
    database = db_path or DEFAULT_DB
    con = sqlite3.connect(database)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    if incident_id is not None:
        rows = cur.execute(
            "SELECT i.*, ai.ip AS intel_ip, ai.abuse_score, ai.country, ai.isp FROM incidents i LEFT JOIN ip_intel ai ON ai.ip = i.src_ip WHERE i.id = ?",
            (incident_id,),
        ).fetchall()
    else:
        rows = cur.execute(
            "SELECT * FROM incidents ORDER BY end_time DESC LIMIT ?",
            (n,),
        ).fetchall()

    con.close()
    return [dict(r) for r in rows]


def export_csv(rows: list, file_path: Path) -> None:
    Path(file_path).parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["id", "src_ip", "dest_ip", "start_time", "end_time", "alert_count", "risk", "status"],
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)


def export_json(rows: list, file_path: Path) -> None:
    Path(file_path).parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)


def export_pdf(rows: list, file_path: Path) -> bool:
    if not HAS_REPORTLAB:
        print(f"Notice: reportlab not installed. Skipping PDF generation for {file_path}")
        return False

    Path(file_path).parent.mkdir(parents=True, exist_ok=True)
    pdf = SimpleDocTemplate(str(file_path), pagesize=letter)
    story = []
    story.append(Paragraph("NetSentinel Incident Report"))
    story.append(Spacer(1, 18))

    data = [["ID", "Source", "Destination", "Risk", "Alerts", "Status"]]
    for row in rows:
        data.append([
            str(row.get("id", "")),
            str(row.get("src_ip", "")),
            str(row.get("dest_ip", "")),
            str(row.get("risk", "")),
            str(row.get("alert_count", "")),
            str(row.get("status", "")),
        ])

    table = Table(data)
    table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f6feb")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("GRID", (0, 0), (-1, -1), 0.8, colors.grey),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
        ])
    )
    story.append(table)
    pdf.build(story)
    return True


def build_report(mode: str = "recent", n: int = 20, incident_id: int = None, db_path: str = None, output_dir: Path = None) -> dict:
    target_dir = Path(output_dir) if output_dir else REPORT_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    rows = fetch_incidents(mode=mode, n=n, incident_id=incident_id, db_path=db_path)
    label = incident_id if incident_id is not None else "latest"
    csv_path = target_dir / f"report_{mode}_{label}.csv"
    json_path = target_dir / f"report_{mode}_{label}.json"
    pdf_path = target_dir / f"report_{mode}_{label}.pdf"

    export_csv(rows, csv_path)
    export_json(rows, json_path)
    pdf_created = export_pdf(rows, pdf_path)

    return {
        "rows": rows,
        "csv": str(csv_path),
        "json": str(json_path),
        "pdf": str(pdf_path) if pdf_created else None,
    }


if __name__ == "__main__":
    result = build_report(mode="recent", n=20)
    print(json.dumps({"pdf": result["pdf"], "csv": result["csv"], "json": result["json"]}, indent=2))
