# In: app/services/threat_service.py

import json
import os
from fastapi import HTTPException

# Define the path to the JSON file relative to the root
# (since run.py is in the root)
ATTACK_LOG_FILE = "attack_log.json"

def get_attack_logs():
    """
    Reads and parses the attack_log.json file.
    """
    if not os.path.exists(ATTACK_LOG_FILE):
        raise HTTPException(status_code=404, detail="attack_log.json not found")
    
    try:
        with open(ATTACK_LOG_FILE, "r") as f:
            data = json.load(f)
            return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading log file: {e}")