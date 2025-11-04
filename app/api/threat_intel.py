# In: app/api/threat_intel.py

from fastapi import APIRouter, Depends
from typing import List, Any
from app.services.threat_service import get_attack_logs

router = APIRouter()

@router.get("/api/v1/attack-logs", response_model=List[Any])
def get_recent_attacks():
    """
    API endpoint to get all attack logs for the dashboard.
    It depends on the threat_service to get the data.
    """
    logs = get_attack_logs()
    return logs