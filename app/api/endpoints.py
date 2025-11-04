# app/api/endpoints.py
from collections import defaultdict
import logging
import os
import json
from urllib.parse import unquote, urlparse
import re
import time
import asyncio
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import (
    APIRouter, Request, HTTPException, WebSocket, WebSocketDisconnect,
    Depends, BackgroundTasks
)
from fastapi.responses import JSONResponse, FileResponse

from ..config import settings
from ..state import app_state
from ..models import EventData, WebsiteMonitorConfig, WebsiteHealth, RiskScore
# Import specific detectors if needed
from ..services.detection import DETECTOR_PIPELINE, calculate_risk_score, detect_llm_anomaly
from ..services.monitoring import start_website_monitoring, stop_website_monitoring
from ..services.notifications import notify_alerts
from ..services.simulation import run_simulation_background_task
from ..utils import get_location_from_ip, log_secure_attack_event
from .websocket import manager

logger = logging.getLogger(__name__)
router = APIRouter()

# --- WebSocket Endpoint ---


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await asyncio.sleep(60)  # Keep alive
    except WebSocketDisconnect as e:
        logger.info(
            f"WS client disconnected: {websocket.client} code={e.code}")
    except Exception as e:
        logger.error(f"WS error {websocket.client}: {e}", exc_info=False)
    finally:
        manager.disconnect(websocket)

# --- Event Logging Endpoint (**Updated Detection Logic**) ---


@router.post("/log_event", status_code=200, summary="Log a security-related event")
async def handle_event(
    request: Request,
    event_data: EventData,
    background_tasks: BackgroundTasks
):
    ip = event_data.source_ip or request.headers.get(
        'X-Forwarded-For') or (request.client.host if request.client else "unknown")
    event_data.source_ip = ip
    timestamp = datetime.now(timezone.utc).isoformat()
    logger.debug(f"Event Received: {event_data.event_type} from IP: {ip}")

    all_detections: List[dict] = []
    critical_found = False

    # --- Run faster detectors first ---
    # Manually call detectors instead of gather, allowing early exit
    for detector in DETECTOR_PIPELINE:
        # Skip LLM detector initially
        if detector.__name__ == 'detect_llm_anomaly':
            continue
        try:
            result = await detector(event_data)
            if result:
                all_detections.append(result)
                if result.get("severity") == "CRITICAL":
                    logger.debug(
                        f"Critical threat '{result.get('attack_type')}' found by {detector.__name__}. Skipping further checks including LLM.")
                    critical_found = True
                    break  # Stop checks if critical found early
        except Exception as e:
            logger.error(
                f"Error running detector {detector.__name__}: {e}", exc_info=True)

    # --- Run LLM detector *only if* no critical threat found yet ---
    if not critical_found:
        try:
            logger.debug(
                "No critical threat found yet, running LLM detector...")
            llm_result = await detect_llm_anomaly(event_data)
            if llm_result:
                all_detections.append(llm_result)
        except Exception as e:
            logger.error(
                f"Error running detect_llm_anomaly: {e}", exc_info=True)

    # --- Process Results ---
    if not all_detections:
        logger.debug(
            f"Event {event_data.event_type} from {ip}: No threat detected.")
        return {"status": "event_logged_no_threat_detected"}

    app_state.error_event_timestamps.append(time.time())
    risk_score: RiskScore = calculate_risk_score(event_data, all_detections)
    primary_attack = max(all_detections, key=lambda x: settings.SEVERITY_WEIGHTS.get(
        x.get("severity", "LOW"), 0))

    initial_report = {**primary_attack, "timestamp": timestamp, "risk_score": risk_score.score, "risk_factors": risk_score.factors, "severity": risk_score.severity,
                      "ip": ip, "city": "...", "country": "...", "lat": 0.0, "lon": 0.0, "event_type": event_data.event_type, "user_id": event_data.user_id, "data": event_data.data}

    log_secure_attack_event(initial_report)
    app_state.attack_history.append(initial_report)
    background_tasks.add_task(notify_alerts, initial_report)
    background_tasks.add_task(
        manager.broadcast, {"type": "attack_detected", **initial_report})
    background_tasks.add_task(
        update_event_with_location, initial_report.copy())

    status_code_to_return = 200
    response_content = {"status": "threat_detected", "details": initial_report}
    if risk_score.severity == "CRITICAL" or risk_score.score >= 0.8:
        rate_limit_until = time.time() + settings.RATE_LIMIT_DURATION
        app_state.rate_limited_ips[ip] = rate_limit_until
        logger.warning(
            f"IP {ip} rate-limited for {settings.RATE_LIMIT_DURATION}s due to {risk_score.severity} event ({primary_attack.get('attack_type', 'N/A')}, Score: {risk_score.score}).")
        status_code_to_return = 403
        response_content = {
            "message": "Access denied due to high-risk activity.", "incident_details": initial_report}

    logger.info(f"Event {event_data.event_type} from {ip}: Detected {risk_score.severity} ({primary_attack.get('attack_type', 'N/A')}). Responding {status_code_to_return}.")
    return JSONResponse(status_code=status_code_to_return, content=response_content)


# --- Background Task Helper for Geolocation (Unchanged) ---
async def update_event_with_location(event_report: dict):
    ip_to_locate = event_report.get("ip")
    event_ts = event_report.get("timestamp")
    if not ip_to_locate or ip_to_locate == "WEBSITE_MONITOR":
        return
    logger.debug(
        f"BG Task: Getting location for IP {ip_to_locate} (Event: {event_ts})")
    location_info = await get_location_from_ip(ip_to_locate)
    logger.debug(f"BG Task: Location for {ip_to_locate}: {location_info}")
    updated_report = event_report.copy()
    updated_report.update(location_info)
    updated_report["update"] = True
    await manager.broadcast({"type": "attack_detected", **updated_report})
    logger.debug(
        f"BG Task: Re-broadcasted event for {ip_to_locate} ({event_ts}) with location.")

# --- Attack Simulation Endpoint (Unchanged) ---


@router.post("/run_simulation", status_code=202, summary="Trigger background attack simulation")
async def trigger_simulation(background_tasks: BackgroundTasks):
    background_tasks.add_task(run_simulation_background_task)
    logger.info("Attack simulation task added to background queue.")
    return {"message": "Attack simulation scheduled successfully."}

# --- Attack Log Retrieval Endpoint (Unchanged) ---


@router.get("/attack_log", response_model=List[dict], summary="Retrieve the attack log")
async def get_attack_log_endpoint():
    log_file = settings.LOG_JSON_FILE
    if not os.path.exists(log_file):
        return []
    try:
        with open(log_file, "r", encoding='utf-8') as f:
            content = f.read()
        if not content:
            return []
        data = json.loads(content)
        if not isinstance(data, list):
            raise HTTPException(
                status_code=500, detail="Invalid log file format.")
        return data
    except Exception as e:
        logger.error(
            f"Error reading attack log {log_file}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, detail="Failed to retrieve attack log.")

# --- Website Monitoring Endpoints (**Updated Scheme Logic**) ---


@router.post("/monitor/website", status_code=200, summary="Add a website to monitor")
async def add_monitor_endpoint(config: WebsiteMonitorConfig):
    url = config.url.strip()
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        # Check if netloc resembles localhost or IP before adding default scheme
        is_local = parsed_url.netloc.startswith(("localhost", "127.0.0.1", "[::1]")) or re.match(
            # Allow port for IP
            r'^\d{1,3}(\.\d{1,3}){3}(:\d+)?$', parsed_url.netloc)
        if is_local and parsed_url.port != 443:
            url = 'http://' + url
            logger.info(f"Assuming HTTP for local address: {url}")
        else:
            url = 'https://' + url
            logger.info(f"Assuming HTTPS for URL: {url}")
        parsed_url = urlparse(url)  # Re-parse

    if parsed_url.scheme not in ['http', 'https'] or not parsed_url.netloc:
        logger.warning(f"Invalid URL: {config.url}")
        raise HTTPException(
            status_code=400, detail=f"Invalid URL format: '{config.url}'.")
    config.url = url
    config.check_interval = max(30, config.check_interval)
    try:
        result = await start_website_monitoring(config.url, config)
        return result
    except Exception as e:
        logger.error(f"Failed start monitor {url}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, detail=f"Failed initiate monitor {url}.")


@router.delete("/monitor/website/{url:path}", status_code=200, summary="Remove a website from monitoring")
async def remove_monitor_endpoint(url: str):
    try:
        decoded_url = unquote(url)
    except Exception as e:
        logger.error(f"Failed decode URL: {url} - {e}")
        raise HTTPException(status_code=400, detail="Invalid URL encoding.")
    if decoded_url not in app_state.monitored_websites:
        logger.warning(f"Attempt remove non-monitored: {decoded_url}")
        raise HTTPException(status_code=404, detail="Website not found.")
    try:
        result = await stop_website_monitoring(decoded_url)
        return result
    except Exception as e:
        logger.error(f"Failed stop monitor: {decoded_url}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, detail=f"Failed stop monitor: {decoded_url}.")


@router.get("/monitor/websites", summary="Get monitored websites and status")
async def get_monitors_endpoint():
    websites_data = []
    monitored_urls = list(app_state.monitored_websites.keys())
    for url in monitored_urls:
        config = app_state.monitored_websites.get(url)
        health_history = app_state.website_health_history.get(url)
        if not config:
            continue
        last_health = health_history[-1] if health_history else None
        config_dict = config.model_dump() if hasattr(
            config, 'model_dump') else config.dict()
        health_dict = last_health.model_dump() if (last_health and hasattr(
            last_health, 'model_dump')) else (last_health.dict() if last_health else None)
        websites_data.append(
            {"url": url, "config": config_dict, "current_health": health_dict})
    return {"websites": websites_data}

# --- Analytics Endpoint (Unchanged) ---


@router.get("/analytics", summary="Get system analytics")
async def get_analytics_endpoint():
    attack_stats = defaultdict(int)
    website_incident_stats = defaultdict(int)
    ip_counts = defaultdict(int)
    history_copy = list(app_state.attack_history)
    incidents_copy = list(app_state.website_incidents)
    for attack in history_copy:
        attack_stats[attack.get("attack_type", "Unknown")] += 1
    for incident in incidents_copy:
        short_type = incident.get(
            "attack_type", "Unknown Incident").replace("WEBSITE_", "")
        website_incident_stats[short_type] += 1
    hour_ago = time.time() - 3600
    for attack in history_copy:
        try:
            ts_str = attack.get('timestamp')
            if ts_str and isinstance(ts_str, str):
                attack_time = datetime.fromisoformat(
                    ts_str.replace('Z', '+00:00')).timestamp()
                if attack_time > hour_ago:
                    ip = attack.get("ip")
                    if ip and ip != "WEBSITE_MONITOR":
                        ip_counts[ip] += 1
        except (ValueError, TypeError) as e:
            logger.warning(
                f"Analytics skip event: timestamp error: {e} - Val: {attack.get('timestamp')}")
            continue
    top_ips = sorted(ip_counts.items(),
                     key=lambda item: item[1], reverse=True)[:5]
    active_rate_limits = len(
        {ip for ip, expiry in app_state.rate_limited_ips.items() if expiry > time.time()})
    return {"attack_type_counts": dict(attack_stats), "website_incident_counts": dict(website_incident_stats), "total_threat_events": len(history_copy), "total_website_incidents": len(incidents_copy), "threat_intelligence_ip_count": len(app_state.ip_threat_blacklist), "rate_limited_ip_count": active_rate_limits, "top_attacking_ips_last_hour": dict(top_ips)}
