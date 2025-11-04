# app/state.py
import asyncio
import threading
from typing import Optional, Dict, List, Deque, Set
from dataclasses import dataclass, field
from collections import deque, defaultdict
import httpx

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .models import WebsiteMonitorConfig


@dataclass
class LLMCircuitState:
    is_open: bool = False
    last_failure_time: float = 0.0
    failure_count: int = 0
    last_error: str = ""


@dataclass
class AppState:
    # Runtime state
    rate_limited_ips: Dict[str, float] = field(default_factory=dict)
    ip_threat_blacklist: Set[str] = field(default_factory=set)
    user_action_log: Dict[str, Deque] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=50)))
    card_failure_log: Dict[str, Deque] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=20)))

    # --- ADD THIS LINE ---
    brute_force_log: Dict[str, Deque] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=20)))
    # --- END ADD ---

    device_fingerprints: Dict[str, List] = field(
        default_factory=lambda: defaultdict(list))

    # System metrics state
    request_timestamps: Deque = field(
        default_factory=lambda: deque(maxlen=500))
    error_event_timestamps: Deque = field(
        default_factory=lambda: deque(maxlen=500))
    ip_request_log: Dict[str, Deque] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=100)))

    # History logs
    attack_history: Deque = field(default_factory=lambda: deque(maxlen=1000))
    website_incidents: Deque = field(default_factory=lambda: deque(maxlen=500))

    # Website monitoring state
    monitored_websites: Dict[str, 'WebsiteMonitorConfig'] = field(
        default_factory=dict)  # Forward reference
    website_health_history: Dict[str, Deque] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=100)))
    website_content_hashes: Dict[str, str] = field(default_factory=dict)
    active_monitoring_tasks: Dict[str, asyncio.Task] = field(
        default_factory=dict)

    # LLM Circuit Breaker state instance
    llm_circuit_state: LLMCircuitState = field(default_factory=LLMCircuitState)

    # Shared resources
    http_client: Optional[httpx.AsyncClient] = None
    log_lock: threading.Lock = field(default_factory=threading.Lock)


# --- Create the app_state instance ---
app_state = AppState()
