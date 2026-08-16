# CyberShield

CyberShield is a cybersecurity log monitoring and threat detection system built with **FastAPI, SQLAlchemy, PostgreSQL, and React**.

It collects security logs, detects suspicious activity, generates alerts, and provides a web dashboard for monitoring and managing detected threats.

## Features

- Security log storage
- Brute-force attack detection
- Suspicious HTTP request detection
- Alert generation and persistence
- Alert status management
- Automatic dashboard refresh
- Alert filtering
- Log searching
- Threat summary
- Recent security logs
- PostgreSQL database integration
- REST API with FastAPI
- Interactive API documentation with Swagger

## Technology Stack

### Backend

- Python
- FastAPI
- SQLAlchemy
- PostgreSQL
- Uvicorn
- Pydantic

### Frontend

- React
- Vite
- JavaScript
- CSS

## System Architecture

```text
                    CyberShield
                         |
              +----------+----------+
              |                     |
         React Frontend        FastAPI Backend
              |                     |
              |              +------+------+
              |              |             |
              |            /logs        /alerts
              |              |             |
              +--------------+-------------+
                             |
                        PostgreSQL
                             |
                    +--------+--------+
                    |                 |
                   logs             alerts
                    |                 |
                    +--------+--------+
                             |
                     Threat Detection
                             |
                 +-----------+-----------+
                 |                       |
            Brute Force         Suspicious Request


Threat Detection

CyberShield currently detects two major threat types.

Brute Force

Detects repeated failed login attempts from the same IP address and username.

Example:

Threat Type: BRUTE_FORCE
Severity: HIGH
IP: 192.168.1.20
Username: admin
Failed Attempts: 6
Suspicious Request

Detects suspicious patterns in HTTP requests.

Example:

Threat Type: SUSPICIOUS_REQUEST
Severity: HIGH
IP: 10.0.0.99
Username: test_user
Request: /login
Alert Management

Detected threats are stored as alerts in PostgreSQL.

Each alert can have one of three statuses:

NEW
REVIEWED
RESOLVED

Status changes are saved to the database and remain after refreshing the dashboard.

Dashboard

The React dashboard provides:

- Total log count
- Total alert count
- High-severity alert count
- New alert count
- Security alert list
- Alert status controls
- Alert status filtering
- Threat summary
- Recent security logs
- Log search
- Automatic data refresh

API Endpoints

Logs
GET /logs

Returns stored security logs.

Alerts
GET /alerts

Returns detected security alerts.

Update Alert Status
PATCH /alerts/{alert_id}

Updates an alert status.

Example request:

{
  "status": "REVIEWED"
}

Allowed statuses:

NEW
REVIEWED
RESOLVED


API Documentation

When the backend is running, interactive Swagger documentation is available at:

http://127.0.0.1:8000/docs

Project Structure

CyberShield/
│
├── backend/
│   ├── services/
│   │   ├── test_detector.py
│   │   ├── test_suspicious.py
│   │   └── threat_detector.py
│   ├── database.py
│   ├── init.py
│   ├── main.py
│   ├── models.py
│   ├── schemas.py
│   └── test_database.py
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── App.css
│   │   ├── index.css
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
│
├── sample_logs/
│   └── security_logs
│
├── .gitignore
└── README.md