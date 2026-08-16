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