# app/utils.py
import json
import hashlib
import logging
import asyncio
import os
from datetime import datetime, timezone
from typing import Dict

# Import config and state (careful with circular imports if utils are needed elsewhere)
from .config import settings
from .state import app_state

# Conditional import for IP Geolocation
try:
    from ip2geotools.databases.noncommercial import DbIpCity
    IP2GEOTOOLS_AVAILABLE = True
except ImportError:
    DbIpCity = None
    IP2GEOTOOLS_AVAILABLE = False
    logging.warning(
        "ip2geotools not installed. IP geolocation will be disabled.")


def mask_pii(data: Dict) -> Dict:
    """Masks PII fields within a dictionary."""
    if not isinstance(data, dict):
        return data  # Return as-is if not a dict

    masked_data = data.copy()
    for field_name in masked_data.keys():
        # Check against PII fields list
        if field_name in settings.PII_FIELDS:
            masked_data[field_name] = "[MASKED]"
        # Specific rule for card number
        elif field_name == "card_number" and isinstance(masked_data[field_name], str) and len(masked_data[field_name]) > 4:
            masked_data[field_name] = f"XXXX-XXXX-XXXX-{masked_data[field_name][-4:]}"
        # Basic check for payment fields containing sensitive-like data (e.g., tokens)
        elif field_name in settings.PAYMENT_FIELDS and isinstance(masked_data[field_name], str) and len(masked_data[field_name]) > 8:
            # Mask longer strings in payment fields generically
            masked_data[field_name] = f"{masked_data[field_name][:4]}...[MASKED]"

    return masked_data


async def get_location_from_ip(ip: str) -> dict:
    """Gets approximate location from IP address using ip2geotools (if available)."""
    default_location = {"city": "Unknown",
                        "country": "Unknown", "lat": 0.0, "lon": 0.0}

    if not IP2GEOTOOLS_AVAILABLE or DbIpCity is None:
        return default_location
    if ip in ["localhost", "127.0.0.1", "::1", "unknown"] or not ip:
        return {"city": "Local", "country": "Local", "lat": 0.0, "lon": 0.0}

    try:
        # Run the blocking DbIpCity.get in a separate thread
        res = await asyncio.to_thread(DbIpCity.get, ip, api_key="free")
        # Ensure lat/lon are floats
        lat = float(res.latitude) if res.latitude is not None else 0.0
        lon = float(res.longitude) if res.longitude is not None else 0.0
        return {"city": res.city or "Unknown", "country": res.country or "Unknown", "lat": lat, "lon": lon}
    except Exception as e:
        # Log the error but don't crash the request
        logging.warning(f"IP Geolocation for {ip} failed: {e}")
        return default_location


def log_secure_attack_event(event: dict):
    """Logs an attack event securely to a JSON file with masking and hashing."""
    if "timestamp" not in event:
        event["timestamp"] = datetime.now(timezone.utc).isoformat()

    # Create a copy for logging to avoid modifying the original event dict
    log_entry = event.copy()

    # Mask PII within the 'data' field if it exists
    if "data" in log_entry and isinstance(log_entry["data"], dict):
        log_entry["data"] = mask_pii(log_entry["data"])
    # Also mask top-level fields if necessary (though usually sensitive data is in 'data')
    log_entry = mask_pii(log_entry)  # Mask top-level just in case

    try:
        # Create hash from the potentially masked log entry for integrity
        log_data_bytes = json.dumps(log_entry, sort_keys=True, default=str).encode(
            'utf-8')  # Use default=str for non-serializable types
        log_entry["integrity_hash"] = hashlib.sha256(
            log_data_bytes).hexdigest()
    except Exception as e:
        logging.error(f"Failed to create integrity hash for log entry: {e}")
        log_entry["integrity_hash"] = "hash_error"

    # Use the log file path from settings
    log_file = settings.LOG_JSON_FILE

    with app_state.log_lock:  # Use the shared lock from app_state
        try:
            # Read existing log or initialize if empty/corrupt/missing
            if os.path.exists(log_file):
                with open(log_file, "r", encoding='utf-8') as f:
                    try:
                        content = f.read()
                        attack_log = json.loads(content) if content else []
                        if not isinstance(attack_log, list):
                            logging.warning(
                                f"Log file {log_file} was not a list, resetting.")
                            attack_log = []
                    except json.JSONDecodeError:
                        logging.warning(
                            f"Log file {log_file} corrupted, resetting.")
                        attack_log = []
            else:
                attack_log = []

            # Append new event
            attack_log.append(log_entry)

            # Write back the entire log (can be inefficient for very large logs)
            with open(log_file, "w", encoding='utf-8') as f:
                json.dump(attack_log, f, indent=2,
                          default=str)  # Use default=str

        except (IOError, json.JSONDecodeError) as e:
            logging.error(f"Failed to write to attack log {log_file}: {e}")
        except Exception as e:
            logging.error(
                f"Unexpected error writing attack log {log_file}: {e}", exc_info=True)
