from datetime import datetime

from pydantic import BaseModel


class LogResponse(BaseModel):
    id: int
    timestamp: datetime
    ip_address: str
    username: str | None = None
    event_type: str
    status: str | None = None
    request: str | None = None
    details: str | None = None

    class Config:
        from_attributes = True


class LogsResponse(BaseModel):
    total: int
    logs: list[LogResponse]


class AlertResponse(BaseModel):
    id: int
    threat_type: str
    severity: str
    ip_address: str
    username: str | None = None
    message: str
    detected_at: datetime
    status: str

    class Config:
        from_attributes = True


class AlertsResponse(BaseModel):
    total: int
    alerts: list[AlertResponse]

class AlertStatusUpdate(BaseModel):
    status: str


class AlertStatusResponse(BaseModel):
    id: int
    threat_type: str
    severity: str
    ip_address: str
    username: str | None = None
    message: str
    detected_at: datetime
    status: str

    class Config:
        from_attributes = True