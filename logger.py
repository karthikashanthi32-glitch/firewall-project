import json
import os
from datetime import datetime

LOG_FILE = "alerts.json"


def _load_logs() -> list:
    """Load existing logs from the JSON file, or return empty list if not found."""
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return []
    return []


def log_alert(src_ip: str, attack_type: str, score: int, action: str = "alert") -> None:
    """
    Append an alert entry to alerts.json.

    Args:
        src_ip:      Source IP address of the suspected attacker.
        attack_type: Type of attack detected (e.g. 'SQL Injection', 'DoS').
        score:       Threat score at time of alert.
        action:      'alert' or 'block' depending on score threshold.
    """
    logs = _load_logs()

    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "src_ip": src_ip,
        "attack_type": attack_type,
        "score": score,
        "action": action,
    }

    logs.append(entry)

    try:
        with open(LOG_FILE, "w") as f:
            json.dump(logs, f, indent=2)
        print(f"[LOG] {action.upper()} | {src_ip} | {attack_type} | score={score}")
    except IOError as e:
        print(f"[ERROR] Could not write to {LOG_FILE}: {e}")


def print_recent_logs(n: int = 10) -> None:
    """Print the last n log entries to stdout (useful for debugging)."""
    logs = _load_logs()
    recent = logs[-n:] if len(logs) >= n else logs
    for entry in recent:
        print(json.dumps(entry, indent=2))