# app/models.py
from typing import Optional, Dict, Any, List
from pydantic import BaseModel

# --- Event Data Model ---


class EventData(BaseModel):
    event_type: str
    user_id: Optional[str] = None
    data: Dict[str, Any] = {}
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    session_id: Optional[str] = None
    device_fingerprint: Optional[Dict[str, Any]] = None

# --- Website Monitoring Configuration Model ---


class WebsiteMonitorConfig(BaseModel):
    url: str
    check_interval: int = 300
    check_ssl: bool = True
    check_uptime: bool = True
    check_content: bool = False
    expected_keywords: List[str] = []
    alert_on_changes: bool = False
    check_security_headers: bool = True
    check_performance: bool = True
    check_tls_security: bool = True
    alert_on_performance: bool = False
    content_change_threshold: float = 0.8

# --- Risk Score Model ---


class RiskScore(BaseModel):
    score: float
    factors: List[str]
    severity: str

# --- Website Health Status Model ---


class WebsiteHealth(BaseModel):
    url: str
    status: str
    response_time: float
    last_check: float
    ssl_days_remaining: Optional[int] = None
    content_hash: Optional[str] = None
    errors: List[str] = []
    security_headers: Dict[str, str] = {}
    content_changes: List[Dict] = []
    performance_metrics: Dict[str, Any] = {}
    tls_version: Optional[str] = None
    certificate_issuer: Optional[str] = None
