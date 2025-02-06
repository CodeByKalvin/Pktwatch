# CodeByKalvin
#
#    _   _ ____   ____ _____ ____
#   | | | |  _ \ / ___|  ___/ ___|
#   | | | | |_) | |   | |_  \___ \
#   | |_| |  _ <| |___|  _|  ___) |
#    \___/|_| \_\\____|_|   |____/
#
#

import logging
import re
import time
import json
from collections import defaultdict
from datetime import datetime
from scapy.all import *
from threading import Thread

# --- Config ---
INTERFACE = "eth0"
FILTER = "tcp or udp"
LOG_FILE = "suspicious.log"
RULE_FILE = "attack_rules.json"
REPORT_FILE = "traffic_report.txt"
MAX_LOGIN_FAILS = 5
LOGIN_WINDOW = 60

# --- Globals ---
running = False
packet_count = 0
alert_count = 0
attack_sigs = {}
alerts = []
login_attempts = defaultdict(list)

# --- Rule Management ---
def load_attack_rules(filename):
    """Load attack rules from JSON.  Handles file absence gracefully."""
    try:
        with open(filename, 'r') as f:
            rules = json.load(f)
    except FileNotFoundError:
        print(f"Rule file '{filename}' missing. Using defaults.")
        rules = {
            "sql_injection": [r"'.*?--", r"union\s+select", r"exec\(", r"\s+or\s+\d+\s*=\s*\d+",
                              r"\s+and\s+1=1", r"information_schema", r";"],
            "cmd_injection": [r"\|", r";", r"`", r"\$\(", r"sh\s+-c"],
            "brute_force": [r"login", r"failed|invalid|incorrect", r"password"],
            "long_payload": {"threshold": 4000}
        }
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON in '{filename}': {e}. Exiting.")
        exit()
    except Exception as e:
        print(f"Unexpected error loading rules: {e}. Exiting.")
        exit()

    # Compile regexes immediately after loading.
    for category, definition in rules.items():
        if isinstance(definition, list):
            try:
                rules[category] = [re.compile(pattern, re.I) for pattern in definition]
            except re.error as e:
                print(f"Regex compilation error for '{category}': {e}. Skipping.")
                del rules[category]  # Remove broken rule
        elif not isinstance(definition, dict):
            print(f"Warning: Unexpected rule definition type for '{category}'. Skipping.")
            del rules[category]

    return rules

def display_asci_art():
    print("""
# CodeByKalvin
#
#    _   _ ____   ____ _____ ____
#   | | | |  _ \\ / ___|  ___/ ___|
#   | | | | |_) | |   | |_  \\___ \\
#   | |_| |  _ <| |___|  _|  ___) |
#    \\___/|_| \\_\\\\____|_|   |____/
#
#
    """)


def setup_logging():
    """Configures logging to file and console."""
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logging.getLogger().addHandler(logging.StreamHandler())  # Also log to console

# --- Packet Processing ---
def extract_packet_info(packet):
    """Extracts key info from a packet."""
    info = {"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "ua": "N/A"}

    if IP in packet:
        info["src_ip"] = packet[IP].src
        info["dst_ip"] = packet[IP].dst

    if TCP in packet:
        info["proto"] = "TCP"
        info["src_port"] = packet[TCP].sport
        info["dst_port"] = packet[TCP].dport
    elif UDP in packet:
        info["proto"] = "UDP"
        info["src_port"] = packet[UDP].sport
        info["dst_port"] = packet[UDP].dport

    if Raw in packet:
        raw_data = packet[Raw].load.decode("utf-8", errors="ignore")
        if "User-Agent:" in raw_data:
            match = re.search(r"User-Agent:\s*(.+)", raw_data)
            info["ua"] = match.group(1).strip() if match else "N/A"

    return info


def analyze_traffic(packet):
    """Main analysis function. Checks for suspicious activity."""
    global packet_count
    packet_count += 1

    packet_info = extract_packet_info(packet)

    if Raw in packet:
        payload = packet[Raw].load.decode("utf-8", errors="ignore")

        if packet_info.get("proto") == "TCP":
            if packet_info.get("dst_port") in (80, 443):
                check_http(payload, packet_info, packet)
            elif packet_info.get("dst_port") == 22:
                check_ssh(payload, packet_info, packet)
        elif packet_info.get("proto") == "UDP" and packet_info.get("dst_port") == 53:
            check_dns(payload, packet_info, packet)

        check_general_attacks(payload, packet_info, packet) #General attacks


def check_http(payload, context, packet):
    """Checks HTTP payload for attacks."""
    for name, sigs in attack_sigs.items():
        if name == "brute_force":
            if any(sig.search(payload) for sig in sigs) and re.search(r"login|signin|auth", payload, re.I):
                if any(sig.search(payload) for sig in sigs) and re.search(r"failed|invalid|incorrect", payload, re.I):
                    handle_failed_login(context, packet)
        elif isinstance(sigs, list): #Check for other signatures
            for sig in sigs:
                if sig.search(payload):
                    report_activity(f"Possible {name} attack", context, packet)
                    return  # Only report once per packet
        elif isinstance(sigs, dict):
            pass



def handle_failed_login(context, packet):
    """Tracks login attempts and flags brute force."""
    ip = context.get("src_ip")
    now = time.time()

    login_attempts[ip].append(now)
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t <= LOGIN_WINDOW]

    if len(login_attempts[ip]) >= MAX_LOGIN_FAILS:
        report_activity(f"Brute force from {ip}", context, packet)
    else:
        report_activity(f"Failed login from {ip}", context, packet)


def check_dns(payload, context, packet):
    """Checks DNS traffic for anomalies."""
    try:
        dns = DNS(payload)
        if dns.qr == 1 and dns.an:  # Response with answer
            for ans in dns.an:
                if ans.type == 1:  # A record
                    report_activity(f"DNS Response: {ans.rdata} for {dns.qd.qname.decode('utf-8')}", context, packet)
    except Exception:
        pass  # Ignore malformed DNS packets


def check_ssh(payload, context, packet):
    """Looks for SSH connection attempts."""
    if "SSH-" in payload:
        report_activity("SSH connection attempt", context, packet)


def check_general_attacks(payload, context, packet):
    """Checks for long payloads"""

    config = attack_sigs.get("long_payload")
    if config and isinstance(config, dict) and "threshold" in config:
        threshold = config["threshold"]
        if len(payload) > threshold:
            report_activity("Long payload detected", context, packet)


def report_activity(message, context, packet):
    """Logs and stores suspicious activity."""
    global alert_count
    alert_count += 1

    log_msg = f"[{context.get('ts')}] {context.get('proto', 'N/A')} {context.get('src_ip', 'N/A')}:{context.get('src_port', 'N/A')} -> {context.get('dst_ip', 'N/A')}:{context.get('dst_port', 'N/A')} - {message}"
    logging.warning(log_msg)
    print(log_msg)

    alerts.append({
        "ts": context['ts'],
        "proto": context['proto'],
        "src_ip": context['src_ip'],
        "src_port": context['src_port'],
        "dst_ip": context['dst_ip'],
        "dst_port": context['dst_port'],
        "message": message,
        "packet": packet
    })

# --- Control Functions ---
def start_capture():
    """Starts the packet capture thread."""
    global running, packet_count, alert_count

    if not running:
        running = True
        packet_count = 0
        alert_count = 0
        print("Starting capture...")
        Thread(target=capture_packets, daemon=True).start()
    else:
        print("Capture already running.")

def stop_capture():
    """Stops the packet capture."""
    global running
    if running:
        running = False
        print("Stopping capture...")


def capture_packets():
    """Captures packets using Scapy."""
    try:
        sniff(iface=INTERFACE, prn=analyze_traffic, filter=FILTER, store=False, stop_filter=lambda x: not running)
    except Exception as e:
        print(f"Capture error: {e}")
    finally:
        stop_capture()


def generate_activity_report():
    """Generates a report of captured traffic and alerts."""
    report = f"Traffic Analysis Report\n"
    report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    report += f"Packets captured: {packet_count}\n"
    report += f"Alerts generated: {alert_count}\n\n"

    if alerts:
        report += "Alerts:\n"
        for alert in alerts:
            report += f"  [{alert['ts']}] {alert['proto']} {alert['src_ip']}:{alert['src_port']} -> {alert['dst_ip']}:{alert['dst_port']} - {alert['message']}\n"
    else:
        report += "No alerts.\n"

    try:
        with open(REPORT_FILE, "w") as f:
            f.write(report)
        print(f"Report saved to '{REPORT_FILE}'.")
    except Exception as e:
        print(f"Error saving report: {e}")

def find_alerts():
    """Searches alerts based on a user-provided term."""
    term = input("Enter search term: ").strip().lower()
    if not term:
        print("No search term provided.")
        return

    matches = [a for a in alerts if term in a['message'].lower()]

    if matches:
        print("Matching alerts:")
        for match in matches:
            print(f"  [{match['ts']}] {match['proto']} {match['src_ip']}:{match['src_port']} -> {match['dst_ip']}:{match['dst_port']} - {match['message']}")
    else:
        print("No matching alerts.")


# --- Main ---
def main():
    """Main loop of the network monitor."""
    display_asci_art()
    setup_logging()
    global attack_sigs
    attack_sigs = load_attack_rules(RULE_FILE)

    while True:
        action = input("Enter command (start, stop, search, report, exit): ").lower().strip()

        if action == "start":
            start_capture()
        elif action == "stop":
            stop_capture()
        elif action == "search":
            find_alerts()
        elif action == "report":
            generate_activity_report()
        elif action == "exit":
            if running:
                stop_capture()
            break
        else:
            print("Invalid command.")


if __name__ == "__main__":
    main()
