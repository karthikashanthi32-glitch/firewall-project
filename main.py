import argparse
import sys

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
except ImportError:
    print("[ERROR] Scapy is not installed. Run: pip install scapy --break-system-packages")
    sys.exit(1)

from detector import analyze_packet, load_lists
from firewall import block_ip, is_blocked
from logger import log_alert

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────
DEFAULT_IFACE   = "eth0"     # Change to "wlan0" if using Wi-Fi
DEFAULT_COUNT   = 0          # 0 = sniff indefinitely
DEFAULT_FILTER  = "ip"       # BPF filter — only capture IP packets

# IPs we never want to block (add your gateway, loopback, etc.)
ALWAYS_ALLOW = set()


def get_protocol(packet) -> str:
    """
    Return a human-readable protocol name from a Scapy packet.

    Args:
        packet: Scapy packet object.

    Returns:
        Protocol string: 'TCP', 'UDP', 'ICMP', or 'OTHER'.
    """
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def extract_payload(packet) -> str:
    """
    Extract the raw payload from a Scapy packet as a decoded string.
    Returns an empty string if no payload or decoding fails.

    Args:
        packet: Scapy packet object.

    Returns:
        Decoded payload string (lossy UTF-8).
    """
    if packet.haslayer(Raw):
        try:
            return packet[Raw].load.decode("utf-8", errors="replace")
        except Exception:
            return ""
    return ""


def process_packet(packet) -> None:
    """
    Callback invoked by Scapy for every captured packet.
    Extracts fields, runs detection, and triggers blocking/alerting.

    Args:
        packet: Raw Scapy packet object.
    """
    # Only process packets with an IP layer
    if not packet.haslayer(IP):
        return

    src_ip   = packet[IP].src
    dst_ip   = packet[IP].dst
    protocol = get_protocol(packet)
    payload  = extract_payload(packet)

    # Skip IPs that should never be blocked
    if src_ip in ALWAYS_ALLOW:
        return

    # Skip if already blocked (avoid redundant analysis)
    if is_blocked(src_ip):
        return

    # Run IDS analysis
    result = analyze_packet(src_ip, dst_ip, protocol, payload)

    action = result["action"]
    score  = result["score"]
    threats = result["threats"]

    if action == "pass":
        return  # Clean packet; nothing to do

    # Print detection summary to console
    threat_str = ", ".join(threats) if threats else "Unknown"
    print(f"[DETECT] {src_ip} → {dst_ip} | {protocol} | threats={threat_str} | score={score} | action={action.upper()}")

    if action == "alert":
        log_alert(src_ip, threat_str, score, action="alert")

    elif action == "block":
        # block_ip also logs internally
        block_ip(src_ip, threat_str, score)


def main():
    """Parse CLI arguments and start the packet sniffer."""
    parser = argparse.ArgumentParser(
        description="Adaptive Firewall IDS/IPS — Packet Sniffer"
    )
    parser.add_argument(
        "--iface", default=DEFAULT_IFACE,
        help=f"Network interface to sniff (default: {DEFAULT_IFACE})"
    )
    parser.add_argument(
        "--count", type=int, default=DEFAULT_COUNT,
        help="Number of packets to capture (0 = infinite)"
    )
    args = parser.parse_args()

    # Load whitelist and blacklist from files (optional, silently skipped if missing)
    load_lists("whitelist.txt", "blacklist.txt")

    print(f"[*] Starting Adaptive Firewall IDS/IPS on interface: {args.iface}")
    print(f"[*] BPF filter: '{DEFAULT_FILTER}' | count: {'∞' if args.count == 0 else args.count}")
    print("[*] Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface=args.iface,
            filter=DEFAULT_FILTER,
            prn=process_packet,
            count=args.count,
            store=False,      # Don't accumulate packets in memory
        )
    except KeyboardInterrupt:
        print("\n[*] Stopping sniffer. Goodbye.")
    except PermissionError:
        print("[ERROR] Permission denied. Run with: sudo python3 main.py")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()