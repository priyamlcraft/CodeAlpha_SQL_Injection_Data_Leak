
import os
import re
import sqlite3
from datetime import datetime, timezone

from flask import Flask, render_template, request
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "security_logs.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv(
    "SECRET_KEY", "local-demo-secret-change-before-deployment"
)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

csrf = CSRFProtect(app)


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS scan_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                finding TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            )
        """)
        db.commit()


def analyze_sql_patterns(text):
    """Educational pattern checks only. Never executes submitted SQL."""
    patterns = [
        (r"\bUNION\s+SELECT\b", "UNION-based SQL pattern"),
        (r"\bOR\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?",
         "Suspicious OR condition"),
        (r"(--|/\*|\*/|;--)", "SQL comment or statement separator"),
        (r"\b(DROP|DELETE|ALTER|TRUNCATE)\s+(TABLE|DATABASE)\b",
         "Destructive SQL keyword combination"),
        (r"\bSLEEP\s*\(", "Time-delay SQL function pattern"),
    ]

    findings = [
        description
        for pattern, description in patterns
        if re.search(pattern, text, re.IGNORECASE)
    ]

    return findings


def analyze_data_leaks(text):
    """Checks demo text for common sensitive-data formats."""
    findings = []

    checks = [
        (r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
         "Email address detected"),
        (r"\b(?:\+91[\s-]?)?[6-9]\d{9}\b",
         "Possible Indian mobile number detected"),
        (r"\b(?:\d[ -]?){13,19}\b",
         "Possible long numeric identifier detected"),
        (r"\b(?:api[_-]?key|password|secret|access[_-]?token)\s*[:=]\s*\S+",
         "Possible credential or secret exposed"),
    ]

    for pattern, description in checks:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append(description)

    return findings


def save_event(scan_type, risk_level, finding):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    with get_db() as db:
        db.execute(
            """
            INSERT INTO scan_events (scan_type, risk_level, finding, scanned_at)
            VALUES (?, ?, ?, ?)
            """,
            (scan_type, risk_level, finding[:250], timestamp)
        )
        db.commit()


def get_dashboard_data():
    with get_db() as db:
        total_scans = db.execute(
            "SELECT COUNT(*) FROM scan_events"
        ).fetchone()[0]

        threats = db.execute(
            """
            SELECT COUNT(*) FROM scan_events
            WHERE risk_level IN ('High', 'Medium')
            """
        ).fetchone()[0]

        safe_scans = db.execute(
            "SELECT COUNT(*) FROM scan_events WHERE risk_level = 'Low'"
        ).fetchone()[0]

        low_risk = db.execute(
            "SELECT COUNT(*) FROM scan_events WHERE risk_level = 'Low'"
        ).fetchone()[0]

        medium_risk = db.execute(
            "SELECT COUNT(*) FROM scan_events WHERE risk_level = 'Medium'"
        ).fetchone()[0]

        high_risk = db.execute(
            "SELECT COUNT(*) FROM scan_events WHERE risk_level = 'High'"
        ).fetchone()[0]

        events = db.execute(
            """
            SELECT id, scan_type, risk_level, finding, scanned_at
            FROM scan_events
            ORDER BY id DESC
            LIMIT 8
            """
        ).fetchall()

    risk_counts = {
        "low": low_risk,
        "medium": medium_risk,
        "high": high_risk
    }

    risk_percentages = {
        level: round((count / total_scans) * 100, 1) if total_scans else 0
        for level, count in risk_counts.items()
    }

    return {
        "total_scans": total_scans,
        "threats": threats,
        "safe_scans": safe_scans,
        "risk_counts": risk_counts,
        "risk_percentages": risk_percentages,
        "events": events
    }


@app.route("/", methods=["GET", "POST"])
def dashboard():
    result = None

    if request.method == "POST":
        scan_type = request.form.get("scan_type", "sql").strip().lower()
        sample_text = request.form.get("sample_text", "").strip()

        if scan_type not in ("sql", "leak"):
            scan_type = "sql"

        if not sample_text:
            result = {
                "risk": "Low",
                "title": "No input provided",
                "messages": ["Enter demo text before starting a scan."],
                "scanned": False
            }
        else:
            if scan_type == "sql":
                findings = analyze_sql_patterns(sample_text)
                label = "SQL Injection Pattern Scan"
            else:
                findings = analyze_data_leaks(sample_text)
                label = "Data Leak Risk Scan"

            if findings:
                risk = "High" if len(findings) >= 2 else "Medium"
                title = "Potential Security Risk Detected"
                messages = findings
                summary = "; ".join(findings)
            else:
                risk = "Low"
                title = "No Known Risk Pattern Found"
                messages = [
                    "No matching patterns were found in this demo input.",
                    "This basic scanner cannot guarantee that data or queries are safe."
                ]
                summary = "No matching demo patterns found"

            save_event(label, risk, summary)

            result = {
                "risk": risk,
                "title": title,
                "messages": messages,
                "scanned": True
            }

    data = get_dashboard_data()

    return render_template(
        "index.html",
        stats=data,
        events=data["events"],
        result=result
    )


@app.errorhandler(413)
def too_large(_error):
    return "Input is too large. Please keep it under 16 KB.", 413


@app.errorhandler(400)
def bad_request(_error):
    return "The request could not be verified. Refresh the page and try again.", 400


initialize_database()

if __name__ == "__main__":
    print("SQL SHIELD is starting...")
    print("Open http://127.0.0.1:5000 in your browser")
    app.run(host="127.0.0.1", port=5000, debug=False)
