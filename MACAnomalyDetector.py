from scapy.all import sniff, ARP, Ether
import time
import json
import csv
import os
import threading
from datetime import datetime

# === CONFIGURATIONS ===
SETUP_DURATION = 15  # seconds for setup mode
WHITELIST_FILE = "whitelist.json"
ALERT_LOG_FILE = "alerts.txt"
OBSERVED_PACKET_LOG_FILE = "observed_packets.csv"

# === GLOBAL VARIABLES ===
whitelist = {}  # MAC -> IP
logged_alerts = set()
mac_ip_map = {}  # Track MAC and IP pairs

# Known vendor OUIs (first 3 bytes of MAC)
KNOWN_OUIS = {
    "f8:a2:d6"
}

# === SETUP MODE ===
def setup_mode():
    print(f"[SETUP MODE] Gathering MAC addresses for {SETUP_DURATION} seconds...")
    captured_devices = {}

    def collect_macs(pkt):
        if pkt.haslayer(ARP):
            mac = pkt[ARP].hwsrc
            ip = pkt[ARP].psrc
            if mac and ip and mac != "ff:ff:ff:ff:ff:ff":
                if mac not in captured_devices:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    captured_devices[mac] = ip
                    print(f"[{timestamp}] [NEW DEVICE] MAC: {mac:<17} | IP: {ip}")

    sniff(prn=collect_macs, store=0, timeout=SETUP_DURATION)

    print(f"[SETUP COMPLETE] {len(captured_devices)} devices detected.")
    global whitelist
    whitelist = captured_devices

    # Save whitelist
    with open(WHITELIST_FILE, "w") as f:
        json.dump(whitelist, f, indent=4)
    print(f"[INFO] Whitelist saved to {WHITELIST_FILE}")


# === DETECTION MODE ===
def detection_mode():
    print("\n[DETECTION MODE] Monitoring for anomalies (Press Ctrl + C to stop)...")
    open(ALERT_LOG_FILE, "w").close()
    # Ensure packet log CSV exists with headers
    if not os.path.exists(PACKET_LOG_FILE):
        with open(PACKET_LOG_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Source MAC", "Destination MAC", "Source IP", "Destination IP"])

    def detect(pkt):
        if pkt.haslayer(ARP):
            src_mac = pkt[ARP].hwsrc
            dst_mac = pkt[ARP].hwdst
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst
            op_code = pkt[ARP].op
            op_status = "REQUEST" if op_code == 1 else "REPLY" if op_code == 2 else f"OP={op_code}"
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Log packet
            with open(PACKET_LOG_FILE, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([timestamp, src_mac, dst_mac, src_ip, dst_ip])
            print(f"[{timestamp}] " f"[ARP:{op_status}] " f"SRC: {src_mac:<17} ({src_ip:<15}) " f"-> DST: {dst_mac:<17} ({dst_ip:<15})")
            
            # Track MAC-IP mapping for duplicate detection
            if src_mac in mac_ip_map:
                if mac_ip_map[src_mac] != src_ip:
                    alert = f"[ALERT - DUPLICATE MAC] {src_mac} seen on multiple IPs: {mac_ip_map[src_mac]} and {src_ip} at {timestamp}"
                    log_alert(alert)
            else:
                mac_ip_map[src_mac] = src_ip

            # Unknown device detection
            if src_mac not in whitelist: #and src_mac not in logged_alerts:
                alert = f"[ALERT - UNKNOWN DEVICE] New MAC detected: {src_mac} ({src_ip}) at {timestamp}"
                log_alert(alert)

            # Suspicious vendor detection
            mac_prefix = src_mac.upper()[0:8]
            if mac_prefix not in KNOWN_OUIS and src_mac not in whitelist: #and src_mac not in logged_alerts:
                alert = f"[ALERT - SUSPICIOUS VENDOR] MAC prefix {mac_prefix} not recognized for {src_mac} ({src_ip}) at {timestamp}"
                log_alert(alert)
                logged_alerts.add(src_mac)

    sniff(prn=detect, store=0)

# === HELPER FUNCTION ===
log_lock = threading.Lock()
def log_alert(message):
    with log_lock:
        print(f"     {message}", flush=True)
        with open(ALERT_LOG_FILE, "a") as f:
            f.write(message + "\n")

# === MAIN EXECUTION ===
if __name__ == "__main__":
    print("=== MAC Address Anomaly Detector ===")
    print("1. Setup Mode (Collect MACs)")
    print("2. Detection Mode (Monitor Network)\n")

    setup_mode()  # Step 1: Collect whitelist for 15 seconds

    try:
        detection_mode()  # Step 2: Run continuous monitoring
    except KeyboardInterrupt:
        print("\n[EXIT] Detection stopped by user.")
        print(f"[INFO] Alerts saved in {ALERT_LOG_FILE}")
        print(f"[INFO] Packet logs saved in {PACKET_LOG_FILE}")
        print(f"[INFO] Whitelist saved in {WHITELIST_FILE}")
