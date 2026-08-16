from datetime import datetime

from backend.database import SessionLocal
from backend.models import Log


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
    db.commit()

    print("Test suspicious log inserted successfully.")

finally:
    db.close()