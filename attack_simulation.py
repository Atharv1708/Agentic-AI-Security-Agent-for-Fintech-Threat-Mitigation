# attack_simulation.py (in project root)
import requests
import time
import json
import random
import argparse
from datetime import datetime
from urllib.parse import urljoin
from typing import List, Dict, Any, Optional
import sys
import traceback

print(f"[SimScript] Started execution at {datetime.now().isoformat()}")


class EthicalAttackSimulator:
    def __init__(self, target_url: str, api_endpoint: str = "/log_event", check_connection: bool = True):
        print("[SimScript] Initializing EthicalAttackSimulator...")
        self.target_url = target_url.rstrip('/')
        self.api_endpoint = api_endpoint
        self.full_url = urljoin(self.target_url, self.api_endpoint)
        self.session = requests.Session()
        self.attack_log = []
        print(f"[SimScript] Target log endpoint: {self.full_url}")

        self.attack_templates = {
            "sqli": {"display_name": "SQL Injection", "event_type": "simulated_sql_injection", "severity": "HIGH", "description": "Ethical SQL injection test", "payloads": [{"username": "admin' OR '1'='1--", "password": "pw"}, {"query": "'; SELECT pg_sleep(2); --"}, {"id": "1 UNION SELECT null, version(), null--"}, ]},
            "xss": {"display_name": "XSS", "event_type": "simulated_xss", "severity": "HIGH", "description": "Ethical XSS test", "payloads": [{"comment": "<script>console.log('SimulatedXSS')</script>"}, {"search": "\"><img src=x onerror=console.error('SimulatedXSS')>"}, {"profile": "javascript:console.warn('SimulatedXSS')"}, ]},
            "payment": {"display_name": "Payment Anomaly", "event_type": "simulated_payment_anomaly", "severity": "MEDIUM", "description": "Ethical payment anomaly test", "payloads": [{"card_number": f"4242-4242-4242-{random.randint(1000, 9999)}", "cvv": f"{random.randint(100, 999)}", "expiry_date": "12/28", "amount": f"{random.uniform(500, 2000):.2f}", "currency": "USD"}, {"payment_token": f"tok_{random.randbytes(12).hex()}", "amount": "1.00", "currency": "EUR"}, ]},
            "card_testing": {"display_name": "Card Testing", "event_type": "payment_failure", "severity": "CRITICAL", "description": "Ethical card testing simulation", "payloads": [{"card_bin": "411111", "payment_token": f"tok_fail_{random.randbytes(8).hex()}", "reason": "Insufficient Funds"}, {"card_bin": "510510", "payment_token": f"tok_fail_{random.randbytes(8).hex()}", "reason": "Invalid CVV"}, {"card_bin": "400000", "payment_token": f"tok_fail_{random.randbytes(8).hex()}", "reason": "Do Not Honor"}, {"card_bin": "411111", "payment_token": f"tok_fail_{random.randbytes(8).hex()}", "reason": "Expired Card"}, {"card_bin": "555555", "payment_token": f"tok_fail_{random.randbytes(8).hex()}", "reason": "Generic Decline"}, ]}
        }

        base_target_url = self.target_url  # Ensure assignment before try/except
        if check_connection:
            try:
                print(
                    f"[SimScript] Checking reachability of base target: {base_target_url}")
                response = self.session.get(base_target_url, timeout=3.0)
                print(
                    f"[SimScript] Target reachability check status: {response.status_code}")
            except requests.exceptions.Timeout:
                print(
                    f"[SimScript] WARNING: Timeout connecting to target {base_target_url}", file=sys.stderr)
            except requests.exceptions.ConnectionError as e:
                print(
                    f"[SimScript] WARNING: Could not connect to target {base_target_url}: {e}", file=sys.stderr)
            except Exception as e:
                print(
                    f"[SimScript] WARNING: An unexpected error occurred reaching target {base_target_url}: {e}", file=sys.stderr)
        else:
            print("[SimScript] Skipping connection check during dummy initialization.")
        print("[SimScript] Simulator Initialized.")

    def log_attack_locally(self, attack_data: Dict[str, Any]):
        attack_data['timestamp'] = datetime.now().isoformat()
        self.attack_log.append(attack_data)

    def send_to_security_system(self, event_type: str, payload: Dict[str, Any], user_id: Optional[str] = None) -> bool:
        event_data = {"event_type": event_type, "data": payload,
                      "source_ip": f"192.168.1.{random.randint(50, 150)}", "user_agent": f"EthicalSim/1.{random.randint(0, 2)}"}
        if user_id:
            event_data["user_id"] = user_id
        print(
            f"[SimScript] Attempting to send: {event_type} to {self.full_url}")
        try:
            # --- INCREASED TIMEOUT HERE ---
            response = self.session.post(
                self.full_url,
                json=event_data,
                headers={"Content-Type": "application/json"},
                timeout=15.0  # Increased from 5.0 to 15.0 seconds
            )
            # --- END TIMEOUT INCREASE ---
            status_symbol = "[OK]" if 200 <= response.status_code < 300 else "[FAIL]"
            print(
                f"[SimScript] Sent: {event_type} -> {status_symbol} {response.status_code}")
            if not (200 <= response.status_code < 300):
                try:
                    error_detail = response.json()
                    print(
                        f"[SimScript] Server Response (Error {response.status_code}): {json.dumps(error_detail)}", file=sys.stderr)
                except json.JSONDecodeError:
                    print(
                        f"[SimScript] Server Response (Error {response.status_code}): {response.text[:200]}...", file=sys.stderr)
                return False
            return True
        except requests.exceptions.Timeout:
            print(
                f"[SimScript] ERROR sending {event_type}: Request timed out after 15s", file=sys.stderr)
            return False  # Updated timeout message
        except requests.exceptions.ConnectionError as e:
            print(
                f"[SimScript] ERROR sending {event_type}: Connection error - {e}", file=sys.stderr)
            return False
        except requests.exceptions.RequestException as e:
            print(
                f"[SimScript] ERROR sending {event_type}: Network error - {e}", file=sys.stderr)
            return False
        except Exception as e:
            print(
                f"[SimScript] ERROR sending {event_type}: Unexpected error - {e}", file=sys.stderr)
            return False

    def simulate_attack_type(self, test_type: str, count: int):
        if test_type not in self.attack_templates:
            print(
                f"[SimScript] ERROR: Unknown test type: {test_type}", file=sys.stderr)
            return
        template = self.attack_templates[test_type]
        print(
            f"\n[SimScript] --- Simulating {count} '{template['display_name']}' Attacks ---")
        payload_list = template.get("payloads", [])
        if not payload_list:
            print("[SimScript] WARNING: No payloads defined.")
            return
        success_count = 0
        for i in range(count):
            payload_index = i % len(
                payload_list) if test_type == "card_testing" else random.randrange(len(payload_list))
            payload = payload_list[payload_index]
            print(f"[SimScript]   Test {i+1}/{count}: Preparing payload...")
            self.log_attack_locally({"attack_type": template['display_name'], "payload": payload,
                                    "severity": template['severity'], "description": template['description']})
            if self.send_to_security_system(template['event_type'], payload):
                success_count += 1
            time.sleep(random.uniform(0.3, 0.6))
        print(
            f"[SimScript] --- Finished '{template['display_name']}'. Sent successfully: {success_count}/{count} ---")

    def simulate_brute_force(self, user_id: str, attempts: int):
        passwords = ["123456", "password", "admin",
                     "qwerty", f"pass{random.randint(10, 99)}"]
        print(
            f"\n[SimScript] --- Simulating {attempts} Brute Force Attempts on '{user_id}' ---")
        success_count = 0
        for i in range(attempts):
            password = random.choice(passwords)
            print(
                f"[SimScript]   Attempt {i+1}/{attempts}: User '{user_id}', Pass '*****'")
            self.log_attack_locally({"attack_type": "Brute Force", "payload": {
                                    "username": user_id, "password": "[MASKED]"}, "severity": "MEDIUM", "user_id": user_id, "description": f"Attempt {i+1}"})
            if self.send_to_security_system("login_failure", {"username": user_id, "password": password}, user_id):
                success_count += 1
            time.sleep(random.uniform(0.2, 0.5))
        print(
            f"[SimScript] --- Finished Brute Force. Sent successfully: {success_count}/{attempts} ---")

    def simulate_dos(self, requests_per_second: int, duration: int):
        print(
            f"\n[SimScript] --- Simulating DoS Traffic ({requests_per_second} req/sec for {duration}s) ---")
        end_time = time.time() + duration
        total_sent = 0
        total_success = 0
        while time.time() < end_time:
            start_sec = time.time()
            sent_this_sec = 0
            success_this_sec = 0
            target_interval = 1.0 / requests_per_second
            while time.time() < start_sec + 1.0 and sent_this_sec < requests_per_second:
                if time.time() >= end_time:
                    break
                loop_start_time = time.time()
                payload = {"req_id": total_sent, "ts": time.time()}
                if self.send_to_security_system("simulated_high_traffic", payload):
                    success_this_sec += 1
                total_sent += 1
                sent_this_sec += 1
                elapsed = time.time() - loop_start_time
                sleep_time = max(0, target_interval - elapsed)
                if sleep_time > 0.001:
                    time.sleep(sleep_time)
            print(
                f"[SimScript]   Second elapsed. Sent: {sent_this_sec}, Succeeded: {success_this_sec}")
            total_success += success_this_sec
            sleep_needed = max(0, start_sec + 1.0 - time.time())
            if sleep_needed > 0.005:
                time.sleep(sleep_needed)
        print(
            f"[SimScript] --- DoS simulation finished. Total Sent: {total_sent}, Succeeded: {total_success} ---")

    def run_comprehensive_test(self, count_per_type: int, brute_force_attempts: int, dos_duration: int, dos_rate: int):
        print("\n" + "=" * 60)
        print("   [SimScript] Starting Comprehensive Simulation")
        print(f"   [SimScript] Target API: {self.full_url}")
        print("=" * 60 + "\n")
        for test_type in self.attack_templates:
            if test_type != "card_testing":
                self.simulate_attack_type(test_type, count_per_type)
        self.simulate_brute_force("simulated_victim", brute_force_attempts)
        self.simulate_attack_type("card_testing", len(
            self.attack_templates["card_testing"]["payloads"]))
        self.simulate_dos(requests_per_second=dos_rate, duration=dos_duration)
        print("\n" + "=" * 60)
        print("   [SimScript] Simulation Completed")
        print(f"   [SimScript] Total events attempted: {len(self.attack_log)}")
        print("=" * 60 + "\n")


def main():
    print("[SimScript] main() function started.")
    parser = argparse.ArgumentParser(description="Ethical Attack Simulator")
    try:
        _attack_choices = list(EthicalAttackSimulator(
            "http://localhost:1", check_connection=False).attack_templates.keys())
    except Exception:
        _attack_choices = ["sqli", "xss", "payment", "card_testing"]
    parser.add_argument(
        "target_url", help="Target URL (e.g., http://localhost:8000)")
    parser.add_argument("--test-type", choices=["all"] + _attack_choices + [
                        "brute", "dos"], default="all", help="Type of test")
    parser.add_argument("--count", type=int, default=2,
                        help="Attacks per type / Brute attempts / DoS req/sec")
    parser.add_argument("--user-id", default="sim_user_main",
                        help="User ID for brute force")
    parser.add_argument("--duration", type=int, default=3,
                        help="DoS duration (seconds)")
    args = parser.parse_args()
    print(f"[SimScript] Arguments parsed: {args}")

    print("\n" + "+" + "-" * 66 + "+")
    print("|" + " " * 18 + "ETHICAL ATTACK SIMULATOR v1.2" + " " * 19 + "|")
    print("|" + " " * 16 + "For Authorized Security Testing Only" + " " * 16 + "|")
    print("+" + "-" * 66 + "+")
    print(
        "\n[SimScript] WARNING: Ensure you have explicit permission before testing.\n")

    is_interactive = sys.stdin.isatty() and sys.stdout.isatty()
    print(f"[SimScript] Interactive mode detected: {is_interactive}")
    proceed = False
    if is_interactive:
        try:
            confirm = input(
                f"[SimScript] Target: {args.target_url}. Run '{args.test_type}' simulation? (y/N): ").lower()
            if confirm == 'y':
                proceed = True
            else:
                print("[SimScript] Simulation cancelled by user.")
                sys.exit(0)
        except EOFError:
            print(
                "[SimScript] WARNING: EOFError reading input, assuming non-interactive and proceeding.", file=sys.stderr)
            proceed = True
        except Exception as e:
            print(
                f"[SimScript] ERROR reading confirmation: {e}. Aborting.", file=sys.stderr)
            sys.exit(1)
    else:
        print(
            f"[SimScript] Running non-interactively. Target: {args.target_url}, Test: {args.test_type}")
        proceed = True

    if not proceed:
        print("[SimScript] Simulation not started.")
        sys.exit(0)

    print("[SimScript] Initializing simulator instance with actual target...")
    simulator = EthicalAttackSimulator(args.target_url, check_connection=True)
    print("[SimScript] Simulator instance created.")
    try:
        print(f"[SimScript] Starting test type: {args.test_type}")
        if args.test_type == "all":
            simulator.run_comprehensive_test(count_per_type=args.count, brute_force_attempts=max(
                3, args.count), dos_duration=args.duration, dos_rate=max(5, args.count))
        elif args.test_type in simulator.attack_templates:
            simulator.simulate_attack_type(args.test_type, args.count)
        elif args.test_type == "brute":
            simulator.simulate_brute_force(args.user_id, args.count)
        elif args.test_type == "dos":
            simulator.simulate_dos(
                requests_per_second=args.count, duration=args.duration)
        print("\n[SimScript] Simulation script finished successfully.")
    except Exception as e:
        print(
            f"\n[SimScript] ERROR: Simulation script failed during execution: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    print("[SimScript] Script invoked directly.")
    main()
