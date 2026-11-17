
import os
import re
import sqlite3
from datetime import datetime, timezone

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for
)

from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from cryptography.exceptions import InvalidTag

from crypto_utils import (
    encrypt_sensitive_data,
    decrypt_sensitive_data
)


# Environment Configuration
load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "security_logs.db")

app = Flask(__name__)

secret_key = os.getenv("SECRET_KEY")

if not secret_key or len(secret_key) < 32:
    raise RuntimeError(
        "A SECRET_KEY of at least 32 characters "
        "must be configured in the .env file."
    )

app.config["SECRET_KEY"] = secret_key

app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

app.config["SESSION_COOKIE_SECURE"] = (
    os.getenv("FLASK_ENV", "").lower() == "production"
)

csrf = CSRFProtect(app)


# Flask Login Configuration
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access SQL SHIELD."


# Database Connection
def get_db():

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


# User Model
class User(UserMixin):

    def __init__(self, user_id, username):
        self.id = str(user_id)
        self.username = username


@login_manager.user_loader
def load_user(user_id):

    try:

        with get_db() as db:

            user = db.execute(
                "SELECT id, username FROM users WHERE id = ?",
                (user_id,)
            ).fetchone()

        if user:
            return User(user["id"], user["username"])

    except (sqlite3.Error, ValueError):
        return None

    return None


# Database Initialization
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

        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS secure_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                encrypted_data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)

        db.commit()


# SQL Injection Pattern Analysis
def analyze_sql_patterns(text):
    """Educational pattern checks only. Never executes submitted SQL."""

    patterns = [

        (
            r"\bUNION\s+SELECT\b",
            "UNION-based SQL pattern"
        ),

        (
            r"\bOR\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?",
            "Suspicious OR condition"
        ),

        (
            r"(--|/\*|\*/|;--)",
            "SQL comment or statement separator"
        ),

        (
            r"\b(DROP|DELETE|ALTER|TRUNCATE)\s+(TABLE|DATABASE)\b",
            "Destructive SQL keyword combination"
        ),

        (
            r"\bSLEEP\s*\(",
            "Time-delay SQL function pattern"
        ),

    ]

    findings = [
        description
        for pattern, description in patterns
        if re.search(pattern, text, re.IGNORECASE)
    ]

    return findings


# Data Leak Analysis
def analyze_data_leaks(text):

    findings = []

    checks = [

        (
            r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
            "Email address detected"
        ),

        (
            r"\b(?:\+91[\s-]?)?[6-9]\d{9}\b",
            "Possible Indian mobile number detected"
        ),

        (
           r"\b(?:\d[ -]?){12,19}\b",
            "Possible long numeric identifier detected"
        ),

        (
            r"\b(?:api[_-]?key|password|secret|access[_-]?token)\s*[:=]\s*\S+",
            "Possible credential or secret exposed"
        ),

    ]

    for pattern, description in checks:

        if re.search(pattern, text, re.IGNORECASE):
            findings.append(description)

    return findings


# Save Security Event
def save_event(scan_type, risk_level, finding):

    timestamp = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    with get_db() as db:

        db.execute(
            """
            INSERT INTO scan_events
            (scan_type, risk_level, finding, scanned_at)
            VALUES (?, ?, ?, ?)
            """,
            (scan_type, risk_level, finding[:250], timestamp)
        )

        db.commit()


# Dashboard Analytics
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
            """
            SELECT COUNT(*) FROM scan_events
            WHERE risk_level = 'Low'
            """
        ).fetchone()[0]

        medium_risk = db.execute(
            """
            SELECT COUNT(*) FROM scan_events
            WHERE risk_level = 'Medium'
            """
        ).fetchone()[0]

        high_risk = db.execute(
            """
            SELECT COUNT(*) FROM scan_events
            WHERE risk_level = 'High'
            """
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
        "low": safe_scans,
        "medium": medium_risk,
        "high": high_risk
    }

    risk_percentages = {
        level: round((count / total_scans) * 100, 1)
        if total_scans else 0
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


# Registration
@app.route("/register", methods=["GET", "POST"])
def register():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    error = None

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):

            error = (
                "Username must be 3-30 characters "
                "and contain only letters, numbers or underscores."
            )

        elif len(password) < 8:

            error = "Password must contain at least 8 characters."

        elif len(password) > 128:

            error = "Password is too long."

        elif password != confirm_password:

            error = "Passwords do not match."

        else:

            password_hash = generate_password_hash(password)

            created_at = datetime.now(timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )

            try:

                with get_db() as db:

                    db.execute(
                        """
                        INSERT INTO users
                        (username, password_hash, created_at)
                        VALUES (?, ?, ?)
                        """,
                        (username, password_hash, created_at)
                    )

                    db.commit()

                return redirect(url_for("login"))

            except sqlite3.IntegrityError:

                error = "This username is already registered."

    return render_template("register.html", error=error)


# Login
@app.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    error = None

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db() as db:

            user = db.execute(
                """
                SELECT id, username, password_hash
                FROM users
                WHERE username = ?
                """,
                (username,)
            ).fetchone()

        if user and check_password_hash(
            user["password_hash"], password
        ):

            login_user(
                User(user["id"], user["username"])
            )

            return redirect(url_for("dashboard"))

        error = "Invalid username or password."

    return render_template("login.html", error=error)


# Logout
@app.route("/logout", methods=["POST"])
@login_required
def logout():

    logout_user()

    return redirect(url_for("login"))


# Secure Vault
@app.route("/secure-vault", methods=["GET", "POST"])
@login_required
def secure_vault():

    error = None
    success = None

    if request.method == "POST":

        record_text = request.form.get(
            "record_text", ""
        ).strip()

        if not record_text:

            error = "Please enter demo text before saving."

        elif len(record_text) > 2000:

            error = "Demo text must be under 2000 characters."

        else:

            try:

                encrypted_data = encrypt_sensitive_data(record_text)

                created_at = datetime.now(timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                )

                with get_db() as db:

                    db.execute(
                        """
                        INSERT INTO secure_records
                        (user_id, encrypted_data, created_at)
                        VALUES (?, ?, ?)
                        """,
                        (
                            int(current_user.id),
                            encrypted_data,
                            created_at
                        )
                    )

                    db.commit()

                success = "Demo record encrypted and saved successfully."

            except (ValueError, TypeError):

                error = (
                    "Encryption configuration error. "
                    "Check the AES key."
                )

    records = []

    with get_db() as db:

        saved_records = db.execute(
            """
            SELECT id, encrypted_data, created_at
            FROM secure_records
            WHERE user_id = ?
            ORDER BY id DESC
            """,
            (int(current_user.id),)
        ).fetchall()

    for record in saved_records:

        try:

            decrypted_text = decrypt_sensitive_data(
                record["encrypted_data"]
            )

            records.append({
                "id": record["id"],
                "data": decrypted_text,
                "created_at": record["created_at"]
            })

        except (InvalidTag, ValueError, TypeError):

            records.append({
                "id": record["id"],
                "data": "Unable to decrypt this record.",
                "created_at": record["created_at"]
            })

    return render_template(
        "secure_vault.html",
        records=records,
        error=error,
        success=success
    )


# Main Dashboard
@app.route("/", methods=["GET", "POST"])
@login_required
def dashboard():

    result = None

    if request.method == "POST":

        scan_type = request.form.get(
            "scan_type", "sql"
        ).strip().lower()

        sample_text = request.form.get(
            "sample_text", ""
        ).strip()

        if scan_type not in ("sql", "leak"):
            scan_type = "sql"

        if not sample_text:

            result = {
                "risk": "Low",
                "title": "No input provided",
                "messages": [
                    "Enter demo text before starting a scan."
                ],
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


# Error Handlers
@app.errorhandler(413)
def too_large(_error):

    return "Input is too large. Please keep it under 16 KB.", 413


@app.errorhandler(400)
def bad_request(_error):

    return (
        "The request could not be verified. "
        "Refresh the page and try again."
    ), 400


# Initialize Database
initialize_database()


if __name__ == "__main__":

    print("SQL SHIELD is starting...")
    print("Open http://127.0.0.1:5000 in your browser")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
