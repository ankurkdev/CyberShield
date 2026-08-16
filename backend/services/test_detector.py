from backend.database import SessionLocal
from backend.services.threat_detector import (
    detect_brute_force,
    detect_suspicious_requests,
)


db = SessionLocal()

try:
    brute_force_threats = detect_brute_force(db)
    suspicious_threats = detect_suspicious_requests(db)

    print("Brute-force threats:", len(brute_force_threats))
    print("Suspicious request threats:", len(suspicious_threats))

    for threat in suspicious_threats:
        print(threat)

finally:
    db.close()