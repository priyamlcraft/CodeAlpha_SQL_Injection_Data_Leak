# SQL SHIELD
## SQL Injection & Data Leak Detection System

SQL SHIELD is a lightweight Flask-based web application developed for the CodeAlpha Cloud Computing Internship – Task 2.

The project demonstrates SQL injection pattern detection, sensitive data leak identification, secure password storage, encrypted data storage, and user authentication.

## Project Objectives

- Identify suspicious SQL injection patterns in submitted text.
- Detect possible exposure of sensitive information.
- Protect database operations using parameterized SQL queries.
- Secure sensitive vault records using AES-256-GCM encryption.
- Protect user accounts with password hashing and authentication.
- Maintain security event logs and dashboard analytics.

## Key Features

### 1. User Authentication
- User registration and login.
- Password hashing using Werkzeug.
- Session-based authentication using Flask-Login.

### 2. SQL Injection Pattern Scanner
- Checks submitted text for selected suspicious SQL patterns.
- Displays detected findings and risk levels.
- Does not execute submitted SQL statements.

### 3. Data Leak Detection
- Identifies possible exposure of email addresses.
- Detects possible Indian mobile numbers.
- Checks for long numeric identifiers.
- Identifies possible exposed credentials or secrets.

### 4. AES-256-GCM Secure Data Vault
- Encrypts sensitive demo records before database storage.
- Uses AES-256-GCM authenticated encryption.
- Uses a randomly generated nonce for encryption.
- Decrypts records for their authorized owner.

### 5. Additional Security Controls
- Parameterized SQL queries.
- CSRF protection using Flask-WTF.
- User-specific access to stored vault records.
- HTTP-only session cookies.
- Environment-based secret configuration.

### 6. Security Dashboard
- Total scan statistics.
- Threat and safe scan counts.
- Risk-level analytics.
- Security event logs.

## Technologies Used

- Python
- Flask
- SQLite
- Flask-Login
- Flask-WTF
- Werkzeug
- Cryptography
- HTML
- CSS
- JavaScript
- python-dotenv

## Project Structure

```text
CodeAlpha_SQL_Injection_Data_Leak/
│
├── app.py
├── crypto_utils.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── templates/
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   └── secure_vault.html
│
├── static/
│   └── style.css
│
├── .env
└── security_logs.db
```

The `.env`, virtual environment, and database files are local files and should not be committed to GitHub.

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/priyamlcraft/CodeAlpha_SQL_Injection_Data_Leak.git
cd CodeAlpha_SQL_Injection_Data_Leak
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root.

Add two independently generated values:

```env
SECRET_KEY=your_generated_flask_secret
AES_256_KEY=your_generated_base64_aes_key
```

Generate a Flask secret key:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Generate a 32-byte AES-256 key:

```bash
python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

Copy the generated values into `.env`. Never publish this file or share the secret keys.

### 5. Run the application

```bash
python app.py
```

Open the application locally:

http://127.0.0.1:5000

Register an account to access the dashboard.

## Security Implementation

### SQL Injection Protection

The application uses parameterized SQL queries for database operations involving user-provided values. This separates SQL commands from data.

The scanner also checks submitted text against a limited collection of suspicious SQL patterns. It is a demonstration tool, not a complete SQL injection detection engine.

### Password Protection

User passwords are stored as salted password hashes using Werkzeug rather than as plaintext or reversible encrypted passwords.

### Sensitive Data Encryption

Secure Vault records are encrypted using AES-256-GCM before being stored in SQLite.

The encryption key is loaded from the environment and is not stored in the source code.

### User Access Control

Authentication and user-specific database queries help ensure that users access only their own secure vault records.

## Testing

The following local checks have been performed:

- User registration and login.
- Login and logout flow.
- Password hash verification.
- SQL pattern scanner checks.
- Data leak pattern detection checks.
- AES-256-GCM encryption and decryption.
- Encrypted record storage verification.
- User-specific vault access verification.
- Parameterized SQL query review.
- Normal CSRF-protected form submissions.

These checks do not constitute a complete security audit.

## Current Project Status

The Flask application has been tested locally.

Cloud deployment and public internet accessibility are not yet configured.

The application currently uses SQLite and Flask's development server. It should not be treated as production-ready until deployment hardening, HTTPS, production server configuration, persistent storage, and additional security testing are completed.

## Future Improvements

- Cloud hosting and HTTPS deployment.
- Production WSGI server configuration.
- Managed database integration.
- Expanded security testing.
- Improved monitoring and alerting.
- More comprehensive detection rules.

## Internship Information

**Internship:** CodeAlpha Cloud Computing Internship

**Task:** Task 2 – Detecting Data Leaks Using SQL Injection

**Project:** SQL SHIELD – SQL Injection & Data Leak Detection System

---

Developed as an educational security project.
