from datetime import datetime

from backend.database import SessionLocal
from backend.models import Log
from backend.services.threat_detector import detect_suspicious_requests


db = SessionLocal()

try:
    test_log = Log(
        timestamp=datetime.now(),
        ip_address="10.0.0.99",
        username="test_user",
        event_type="HTTP_REQUEST",
        status="Failed",
        request="/login",
        details="SQL error: ' OR '1'='1",
    )

    db.add(test_log)
    db.flush()

    threats = detect_suspicious_requests(db)

    matching_threat = next(
        (
            threat
            for threat in threats
            if threat["ip_address"] == "10.0.0.99"
            and threat["username"] == "test_user"
        ),
        None,
    )

    assert matching_threat is not None
    assert matching_threat["threat_type"] == "SUSPICIOUS_REQUEST"

    print("SUCCESS: Suspicious request detection works.")

finally:
    db.rollback()
    db.close()