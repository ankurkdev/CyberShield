from sqlalchemy.orm import Session

from backend.models import Log, Alert


FAILED_LOGIN_THRESHOLD = 3


def detect_brute_force(db: Session):
    failed_logs = (
        db.query(Log)
        .filter(Log.event_type == "LOGIN_FAILED")
        .all()
    )

    attempts_by_ip = {}

    for log in failed_logs:
        attempts_by_ip.setdefault(log.ip_address, []).append(log)

    threats = []

    for ip_address, logs in attempts_by_ip.items():
        if len(logs) >= FAILED_LOGIN_THRESHOLD:
            threats.append(
                {
                    "threat_type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "ip_address": ip_address,
                    "username": logs[0].username,
                    "failed_attempts": len(logs),
                    "message": (
                        f"Possible brute-force attack detected from "
                        f"{ip_address}"
                    ),
                }
            )

    return threats

SUSPICIOUS_REQUEST_PATTERNS = [
    "union select",
    "or 1=1",
    "' or '",
    "drop table",
    "<script",
]


def detect_suspicious_requests(db: Session):
    logs = db.query(Log).all()

    threats = []

    for log in logs:
        request_text = (
            f"{log.request or ''} {log.details or ''}"
        ).lower()

        for pattern in SUSPICIOUS_REQUEST_PATTERNS:
            if pattern in request_text:
                threats.append(
                    {
                        "threat_type": "SUSPICIOUS_REQUEST",
                        "severity": "HIGH",
                        "ip_address": log.ip_address,
                        "username": log.username,
                        "event_type": log.event_type,
                        "request": log.request,
                        "matched_pattern": pattern,
                        "message": (
                            f"Suspicious request pattern detected "
                            f"from {log.ip_address}"
                        ),
                    }
                )
                break

    return threats

def save_threats_as_alerts(db: Session, threats: list):
    saved_alerts = []

    for threat in threats:
        existing_alert = (
            db.query(Alert)
            .filter(
                Alert.threat_type == threat["threat_type"],
                Alert.ip_address == threat["ip_address"],
                Alert.username == threat.get("username"),
                Alert.status == "NEW",
            )
            .first()
        )

        if existing_alert:
            continue

        alert = Alert(
            threat_type=threat["threat_type"],
            severity=threat["severity"],
            ip_address=threat["ip_address"],
            username=threat.get("username"),
            message=threat["message"],
            status="NEW",
        )

        db.add(alert)
        saved_alerts.append(alert)

    db.commit()

    return saved_alerts