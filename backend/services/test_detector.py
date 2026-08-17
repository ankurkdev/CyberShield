from datetime import datetime

from backend.database import SessionLocal
from backend.models import Log
from backend.services.threat_detector import (
    detect_brute_force,
    detect_suspicious_requests,
)


db = SessionLocal()

try:
    # Test brute-force detection for one IP + username.
    for _ in range(3):
        db.add(
            Log(
                timestamp=datetime.now(),
                ip_address="192.168.50.10",
                username="test_admin",
                event_type="LOGIN_FAILED",
                status="Failed",
                request="/login",
                details="Invalid password",
            )
        )

    # Test that failures for another username are treated separately.
    for _ in range(2):
        db.add(
            Log(
                timestamp=datetime.now(),
                ip_address="192.168.50.10",
                username="other_user",
                event_type="LOGIN_FAILED",
                status="Failed",
                request="/login",
                details="Invalid password",
            )
        )

    db.flush()

    brute_force_threats = detect_brute_force(db)

    matching_brute_force = next(
        (
            threat
            for threat in brute_force_threats
            if threat["ip_address"] == "192.168.50.10"
            and threat["username"] == "test_admin"
        ),
        None,
    )

    assert matching_brute_force is not None
    assert matching_brute_force["failed_attempts"] >= 3

    # The other_user account has only two failures.
    other_user_threat = next(
        (
            threat
            for threat in brute_force_threats
            if threat["ip_address"] == "192.168.50.10"
            and threat["username"] == "other_user"
        ),
        None,
    )

    assert other_user_threat is None

    # Test suspicious-request detection.
    db.add(
        Log(
            timestamp=datetime.now(),
            ip_address="192.168.50.20",
            username="test_user",
            event_type="HTTP_REQUEST",
            status="Failed",
            request="/login",
            details="SQL error: ' OR '1'='1",
        )
    )

    db.flush()

    suspicious_threats = detect_suspicious_requests(db)

    matching_suspicious = next(
        (
            threat
            for threat in suspicious_threats
            if threat["ip_address"] == "192.168.50.20"
            and threat["username"] == "test_user"
        ),
        None,
    )

    assert matching_suspicious is not None
    assert matching_suspicious["threat_type"] == "SUSPICIOUS_REQUEST"

    print("SUCCESS: Threat detection tests passed.")

finally:
    db.rollback()
    db.close()