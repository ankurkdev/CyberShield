from fastapi.middleware.cors import CORSMiddleware

from backend.services.threat_detector import (
    detect_brute_force,
    detect_suspicious_requests,
    save_threats_as_alerts,
)
import csv
import io
from datetime import datetime

from fastapi import FastAPI, UploadFile, File, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.schemas import (
    AlertStatusResponse,
    AlertStatusUpdate,
    AlertsResponse,
    LogsResponse,
)

from backend.database import Base, engine, get_db
from backend.models import Log, Alert


Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="CyberShield API",
    description="Cybersecurity Log Analysis and Threat Detection System",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {
        "message": "CyberShield API is running",
        "status": "online",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "CyberShield API",
    }


@app.post("/logs/upload")
async def upload_logs(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    contents = await file.read()
    text = contents.decode("utf-8")

    reader = csv.DictReader(io.StringIO(text))

    inserted = 0

    for row in reader:
        log = Log(
            timestamp=datetime.fromisoformat(row["timestamp"]),
            ip_address=row["ip_address"],
            username=row.get("username"),
            event_type=row["event_type"],
            status=row.get("status"),
            request=row.get("request"),
            details=row.get("details"),
        )

        db.add(log)
        inserted += 1

    db.commit()

    return {
        "filename": file.filename,
        "message": "Logs uploaded successfully",
        "records_inserted": inserted,
    }


@app.get("/logs", response_model=LogsResponse)
def get_logs(db: Session = Depends(get_db)):
    logs = db.query(Log).order_by(Log.timestamp.desc()).all()

    return {
        "total": len(logs),
        "logs": logs,
    }

    return {
        "filename": file.filename,
        "message": "Logs uploaded successfully",
        "records_inserted": inserted,
    }

@app.get("/threats")
def get_threats(db: Session = Depends(get_db)):
    brute_force_threats = detect_brute_force(db)
    suspicious_request_threats = detect_suspicious_requests(db)

    threats = brute_force_threats + suspicious_request_threats

    save_threats_as_alerts(db, threats)

    return threats

@app.get("/alerts", response_model=AlertsResponse)
def get_alerts(db: Session = Depends(get_db)):
    alerts = (
        db.query(Alert)
        .order_by(Alert.detected_at.desc())
        .all()
    )

    return {
        "total": len(alerts),
        "alerts": alerts,
    }

@app.get("/analytics")
def get_analytics(db: Session = Depends(get_db)):
    total_logs = db.query(Log).count()
    total_alerts = db.query(Alert).count()

    new_alerts = (
        db.query(Alert)
        .filter(Alert.status == "NEW")
        .count()
    )

    reviewed_alerts = (
        db.query(Alert)
        .filter(Alert.status == "REVIEWED")
        .count()
    )

    resolved_alerts = (
        db.query(Alert)
        .filter(Alert.status == "RESOLVED")
        .count()
    )

    high_severity = (
        db.query(Alert)
        .filter(Alert.severity == "HIGH")
        .count()
    )

    medium_severity = (
        db.query(Alert)
        .filter(Alert.severity == "MEDIUM")
        .count()
    )

    low_severity = (
        db.query(Alert)
        .filter(Alert.severity == "LOW")
        .count()
    )

    threat_type_rows = (
        db.query(Alert.threat_type, func.count(Alert.id))
        .group_by(Alert.threat_type)
        .all()
    )

    threat_types = {
        threat_type: count
        for threat_type, count in threat_type_rows
    }

    top_ip_rows = (
        db.query(Alert.ip_address, func.count(Alert.id))
        .group_by(Alert.ip_address)
        .order_by(func.count(Alert.id).desc())
        .limit(10)
        .all()
    )

    top_ips = {
        ip_address: count
        for ip_address, count in top_ip_rows
    }

    activity_rows = (
        db.query(
            func.date(Alert.detected_at),
            func.count(Alert.id),
        )
        .group_by(func.date(Alert.detected_at))
        .order_by(func.date(Alert.detected_at))
        .all()
    )

    activity_over_time = [
        {
            "date": str(date),
            "alerts": count,
        }
        for date, count in activity_rows
    ]

    return {
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "alert_status": {
            "NEW": new_alerts,
            "REVIEWED": reviewed_alerts,
            "RESOLVED": resolved_alerts,
        },
        "severity": {
            "HIGH": high_severity,
            "MEDIUM": medium_severity,
            "LOW": low_severity,
        },
        "threat_types": threat_types,
        "top_ips": top_ips,
        "activity_over_time": activity_over_time,
    }



@app.patch(
    "/alerts/{alert_id}",
    response_model=AlertStatusResponse,
)
def update_alert_status(
    alert_id: int,
    update: AlertStatusUpdate,
    db: Session = Depends(get_db),
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
    )

    status = update.status.strip().upper()

    if status not in {"NEW", "REVIEWED", "RESOLVED"}:
       raise HTTPException(
             status_code=400,
             detail={
                 "message": "Invalid status",
                 "allowed_statuses": [
                    "NEW",
                    "REVIEWED",
                    "RESOLVED",
                ],
            },
        )

    alert.status = status
    db.commit()
    db.refresh(alert)

    return alert