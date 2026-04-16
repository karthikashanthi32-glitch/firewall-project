import re
import time
from collections import defaultdict

# ──────────────────────────────────────────────
# Threat score thresholds
# ──────────────────────────────────────────────
SCORE_ALERT = 30    # Log an alert
SCORE_BLOCK = 80    # Block the IP via iptables

# ──────────────────────────────────────────────
# Signature patterns (regex)
# ──────────────────────────────────────────────
SIGNATURES = {
    "SQL Injection":   re.compile(r"('|\%27).*(OR|AND|UNION|SELECT|INSERT|DROP|--|\%2D\%2D)", re.IGNORECASE),
    "XSS":             re.compile(r"<\s*script.*?>|javascript\s*:", re.IGNORECASE),
    "Path Traversal":  re.compile(r"\.\./|\.\.\\|%2e%2e%2f|%2e%2e/", re.IGNORECASE),
    "Command Inject":  re.compile(r"(;|\||\`)\s*(ls|cat|wget|curl|nc|bash|sh|chmod|rm)\b", re.IGNORECASE),
}

# ──────────────────────────────────────────────
# Behavioral DoS detection config
# ──────────────────────────────────────────────
DOS_THRESHOLD   = 100    # Packets from one IP within...
DOS_WINDOW      = 5      # ...this many seconds → DoS flag

# Stores list of timestamps per source IP
_packet_times: dict = defaultdict(list)

# ──────────────────────────────────────────────
# Whitelist / Blacklist (loaded from text files)
# ──────────────────────────────────────────────
_whitelist: set = set()
_blacklist: set = set()


def load_lists(whitelist_file: str = "whitelist.txt",
               blacklist_file: str = "blacklist.txt") -> None:
    """
    Load IP addresses from whitelist.txt and blacklist.txt.
    Each file should have one IP per line. Lines starting with '#' are comments.

    Args:
        whitelist_file: Path to the whitelist file.
        blacklist_file: Path to the blacklist file.
    """
    global _whitelist, _blacklist
    _whitelist = _load_ip_file(whitelist_file)
    _blacklist = _load_ip_file(blacklist_file)
    print(f"[DETECTOR] Loaded {len(_whitelist)} whitelisted, {len(_blacklist)} blacklisted IPs.")


def _load_ip_file(path: str) -> set:
    """Read a text file of IPs (one per line) into a set."""
    ips = set()
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    ips.add(line)
    except FileNotFoundError:
        pass  # File is optional; silently skip
    return ips


# ──────────────────────────────────────────────
# Core analysis function
# ──────────────────────────────────────────────

def analyze_packet(src_ip: str, dst_ip: str, protocol: str, payload: str) -> dict:
    """
    Analyze a single packet and return a result dict with threats and score.

    Args:
        src_ip:   Source IP address string.
        dst_ip:   Destination IP address string.
        protocol: Protocol name (TCP, UDP, ICMP, etc.).
        payload:  Raw payload string decoded from the packet.

    Returns:
        A dict with keys:
          - src_ip (str)
          - threats (list of str): detected attack types
          - score (int): total threat score
          - action (str): 'pass', 'alert', or 'block'
    """
    threats = []
    score = 0

    # 1. Whitelist: skip analysis entirely for trusted IPs
    if src_ip in _whitelist:
        return {"src_ip": src_ip, "threats": [], "score": 0, "action": "pass"}

    # 2. Blacklist: instant maximum score
    if src_ip in _blacklist:
        threats.append("Blacklisted IP")
        score += 100

    # 3. Signature-based detection on payload
    if payload:
        for attack_name, pattern in SIGNATURES.items():
            if pattern.search(payload):
                threats.append(attack_name)
                score += 50

    # 4. Behavioral DoS detection
    if _is_dos(src_ip):
        threats.append("DoS / Flood")
        score += 40

    # 5. Determine action based on score thresholds
    if score >= SCORE_BLOCK:
        action = "block"
    elif score >= SCORE_ALERT:
        action = "alert"
    else:
        action = "pass"

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "threats": threats,
        "score": score,
        "action": action,
    }


def _is_dos(src_ip: str) -> bool:
    """
    Check whether src_ip has exceeded DOS_THRESHOLD packets in the last DOS_WINDOW seconds.

    Args:
        src_ip: Source IP to evaluate.

    Returns:
        True if DoS threshold exceeded, False otherwise.
    """
    now = time.time()
    window_start = now - DOS_WINDOW

    # Record this packet's timestamp
    _packet_times[src_ip].append(now)

    # Drop timestamps outside the sliding window to keep memory bounded
    _packet_times[src_ip] = [t for t in _packet_times[src_ip] if t >= window_start]

    return len(_packet_times[src_ip]) > DOS_THRESHOLD