import subprocess
import threading
import time
from logger import log_alert

# How long (seconds) a blocked IP stays blocked before auto-unblock
BLOCK_DURATION = 30 * 60  # 30 minutes

# In-memory set of currently blocked IPs (avoids duplicate iptables rules)
_blocked_ips: set = set()
_lock = threading.Lock()


def _run_iptables(args: list) -> bool:
    """
    Execute an iptables command via subprocess.

    Args:
        args: List of iptables arguments (e.g. ['-A', 'INPUT', '-s', '1.2.3.4', '-j', 'DROP']).

    Returns:
        True if successful, False otherwise.
    """
    cmd = ["iptables"] + args
    try:
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] iptables failed: {e.stderr.strip()}")
        return False
    except FileNotFoundError:
        print("[ERROR] iptables not found. Are you running as root on Linux?")
        return False


def block_ip(src_ip: str, attack_type: str, score: int) -> None:
    """
    Block a source IP using iptables DROP rule.
    Schedules auto-unblock after BLOCK_DURATION seconds.

    Args:
        src_ip:      IP address to block.
        attack_type: Reason for blocking (logged).
        score:       Threat score (logged).
    """
    with _lock:
        if src_ip in _blocked_ips:
            print(f"[FIREWALL] {src_ip} is already blocked.")
            return

        success = _run_iptables(["-I", "INPUT", "-s", src_ip, "-j", "DROP"])
        if success:
            _blocked_ips.add(src_ip)
            print(f"[FIREWALL] BLOCKED {src_ip} (reason: {attack_type}, score: {score})")
            log_alert(src_ip, attack_type, score, action="block")

            # Schedule automatic unblock in a background thread
            timer = threading.Timer(BLOCK_DURATION, _auto_unblock, args=[src_ip])
            timer.daemon = True  # Won't prevent program exit
            timer.start()
        else:
            print(f"[FIREWALL] Failed to block {src_ip}")


def unblock_ip(src_ip: str) -> None:
    """
    Remove the iptables DROP rule for a given IP.

    Args:
        src_ip: IP address to unblock.
    """
    with _lock:
        if src_ip not in _blocked_ips:
            print(f"[FIREWALL] {src_ip} is not in the blocked list.")
            return

        success = _run_iptables(["-D", "INPUT", "-s", src_ip, "-j", "DROP"])
        if success:
            _blocked_ips.discard(src_ip)
            print(f"[FIREWALL] UNBLOCKED {src_ip}")
        else:
            print(f"[FIREWALL] Failed to unblock {src_ip}")


def _auto_unblock(src_ip: str) -> None:
    """
    Called automatically by a timer thread after BLOCK_DURATION seconds.
    Unblocks the IP and logs the event.

    Args:
        src_ip: IP address to unblock.
    """
    print(f"[FIREWALL] Auto-unblocking {src_ip} after {BLOCK_DURATION // 60} minutes.")
    unblock_ip(src_ip)


def is_blocked(src_ip: str) -> bool:
    """
    Check whether an IP is currently in the blocked set.

    Args:
        src_ip: IP address to check.

    Returns:
        True if blocked, False otherwise.
    """
    with _lock:
        return src_ip in _blocked_ips


def get_blocked_ips() -> set:
    """Return a copy of the currently blocked IP set."""
    with _lock:
        return set(_blocked_ips)