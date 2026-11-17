# SQL SHIELD – SQL Injection & Data Leak Detection System

## Internship Information

- **Organization:** CodeAlpha
- **Internship Domain:** Cloud Computing
- **Project Title:** SQL Injection & Data Leak Detection System
- **Project Category:** Security Monitoring

## Project Overview

SQL SHIELD is a Python-based security monitoring application developed as part of the CodeAlpha Internship.

The application provides a web-based dashboard for identifying selected SQL injection patterns and potential sensitive data exposure in sample input. It also maintains scan records using an SQLite database.

This project demonstrates web application development, backend processing, database integration, and security monitoring concepts relevant to secure cloud-based applications.

## Key Features

- SQL Injection Pattern Detection
- Sensitive Data Leak Detection
- Risk Level Classification (Low, Medium, High)
- Security Event Logging
- SQLite Database Integration
- Dashboard with Scan Statistics
- CSRF Protection
- Responsive Web Interface
- Local Security Scan History

## Technologies Used

- **Programming Language:** Python
- **Backend Framework:** Flask
- **Database:** SQLite
- **Security:** Flask-WTF (CSRF Protection)
- **Frontend:** HTML5, CSS3
- **Pattern Detection:** Regular Expressions
- **Environment Configuration:** python-dotenv

## Project Structure

```text
CodeAlpha_SQL_Injection_Data_Leak/
│
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── templates/
│   └── index.html
│
└── static/
    └── style.css
```

## Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/priyamlcraft/CodeAlpha_SQL_Injection_Data_Leak.git
```

### 2. Navigate to the Project Folder

```bash
cd CodeAlpha_SQL_Injection_Data_Leak
```

### 3. Create a Virtual Environment

```bash
python -m venv .venv
```

### 4. Activate the Environment

For Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 5. Install Dependencies

```bash
pip install -r requirements.txt
```

### 6. Run the Application

```bash
python app.py
```

Open your browser and visit:

```text
http://127.0.0.1:5000
```

## How It Works

1. Open the SQL SHIELD dashboard.
2. Select a scan category:
   - SQL Injection Pattern Detection
   - Sensitive Data Leak Detection
3. Enter sample text for analysis.
4. Click the Security Scan button.
5. View the detected pattern and assigned risk level.
6. Review previous scan activities in the Security Event Logs section.

## Cloud Computing Relevance

This project explores concepts relevant to secure cloud-based application development:

- Web-based application architecture
- Backend processing using Python Flask
- Database integration and record management
- Application-level security monitoring
- Secure handling of user input
- Understanding application security in cloud environments

**Deployment Status:** The current version runs locally and has not yet been deployed to a cloud platform.

## Security Notes

- This project is designed for educational and demonstration purposes.
- It uses basic pattern matching and is not a complete security scanner.
- User-provided SQL statements are not executed.
- Raw scan input is not stored in the event log; only scan summaries are recorded.
- Do not use this application as a replacement for professional security testing.

## Future Improvements

- Cloud platform deployment
- Cloud database integration
- Enhanced security monitoring
- Improved reporting and analytics
- User authentication and role-based access

## Project Information

- **Project Name:** SQL SHIELD
- **Internship Organization:** CodeAlpha
- **Internship Domain:** Cloud Computing
- **Project Focus:** SQL Injection Pattern Detection and Data Leak Monitoring
- **Application Type:** Web-Based Security Monitoring System

---

*Developed as part of the CodeAlpha Internship for educational purposes.*

## Testing Results

The SQL SHIELD application was tested using different sample inputs in a local educational environment.

### Test Summary

| Test Case | Scan Category | Expected Result | Status |
|---|---|---|---|
| Normal SQL Query | SQL Injection Pattern Detection | Low Risk | Passed |
| UNION SELECT Pattern | SQL Injection Pattern Detection | Medium Risk | Passed |
| Email Address Detection | Sensitive Data Leak Detection | Medium Risk | Passed |
| SQL Comment Pattern | SQL Injection Pattern Detection | Medium Risk | Passed |
| Multiple Suspicious Patterns | SQL Injection Pattern Detection | High Risk | Passed |

### Testing Observations

- Identified selected SQL injection-related patterns.
- Detected potential sensitive information such as email addresses.
- Classified results into Low, Medium, and High risk levels.
- Stored scan summaries and timestamps in SQLite.
- Displayed scan statistics and recent events on the dashboard.

### Testing Environment

- Operating System: Windows
- Programming Language: Python
- Framework: Flask
- Database: SQLite
- Testing Type: Local Functional Testing

**Note:** These tests validate predefined pattern-matching rules only. They do not guarantee complete SQL injection protection or detection of all sensitive data exposure.

