from scapy.all import sniff, ARP, Ether, IP
import json
import csv
import os
import threading
from datetime import datetime
import ipaddress

SETUP_DURATION = 60
WHITELIST_FILE = "whitelist.json"
ALERT_LOG_FILE = "alerts.txt"
OBSERVED_PACKET_LOG_FILE = "observed_packets.csv"

whitelist = {}
logged_alerts = set()
ip_mac_map = { }

# Known vendor OUIs (first 3 bytes of MAC)
KNOWN_OUIS = {
    "F8:A2:D6"
}

# === FILTERING ===
def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except Exception:
        return False

def is_multicast_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_multicast
    except Exception:
        return False

def is_multicast_or_broadcast_mac(mac: str) -> bool:
    if not mac:
        return False
    m = mac.lower()
    return (
        m == "ff:ff:ff:ff:ff:ff" or  # broadcast
        m.startswith("01:00:5e") or  # IPv4 multicast
        m.startswith("33:33:")      # IPv6 multicast
    )

# === SETUP MODE ===
def setup_mode():
    print(f"[SETUP MODE] Gathering MAC addresses for {SETUP_DURATION} seconds...")
    captured_devices = {}

    def collect_macs(pkt):
        mac, ip = None, None

        if pkt.haslayer(ARP) and pkt[ARP].op in (1, 2):
            mac = pkt[ARP].hwsrc
            ip = pkt[ARP].psrc
        elif pkt.haslayer(Ether) and pkt.haslayer(IP):
            mac = pkt[Ether].src
            ip  = pkt[IP].src
        else:
            return

        if not mac or is_multicast_or_broadcast_mac(mac):
            return
        if not is_private_ip(ip):
            return

        if mac not in captured_devices:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            captured_devices[mac] = ip
            print(f"[{timestamp}] [NEW DEVICE] MAC: {mac} | IP: {ip}")

    sniff(prn=collect_macs, store=0, timeout=SETUP_DURATION, filter="arp or (ip and not icmp)")

    print(f"[SETUP COMPLETE] {len(captured_devices)} devices detected.")

    # Load existing whitelist (CRITICAL for appending without overriding)
    global whitelist
    if os.path.exists(WHITELIST_FILE) and os.path.getsize(WHITELIST_FILE) > 0:
        try:
            with open(WHITELIST_FILE, "r") as f:
                # Use update() to load the existing list into the global 'whitelist' dictionary
                whitelist.update(json.load(f))
        except json.JSONDecodeError:
            print(f"[WARNING] Could not decode existing {WHITELIST_FILE}. Starting with an empty whitelist.")
            whitelist = {}
        except Exception as e:
            print(f"[ERROR] Could not load existing whitelist: {e}. Starting with an empty whitelist.")
            whitelist = {}

    # Merge new devices, avoid duplicates
    added_count = 0
    for mac, ip in captured_devices.items():
        if mac not in whitelist:
            whitelist[mac] = ip
            added_count += 1

    # Save updated whitelist (Use "w" to overwrite the complete, merged dictionary)
    with open(WHITELIST_FILE, "w") as f:
        json.dump(whitelist, f, indent=4)

    print(f"[INFO] {added_count} new device(s) added to whitelist. Total whitelist size: {len(whitelist)}")

# === DETECTION MODE ===
def detection_mode():
    print("\n[DETECTION MODE] Monitoring for anomalies (Press Ctrl + C to stop)...")
    open(ALERT_LOG_FILE, "w").close()
    if not os.path.exists(OBSERVED_PACKET_LOG_FILE):
        with open(OBSERVED_PACKET_LOG_FILE, "w", newline="") as f:
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

            with open(OBSERVED_PACKET_LOG_FILE, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([timestamp, src_mac, dst_mac, src_ip, dst_ip])

            if is_private_ip(src_ip) and is_private_ip(dst_ip) and not is_multicast_or_broadcast_mac(src_mac) and not is_multicast_or_broadcast_mac(dst_mac):
                print(f"[{timestamp}] " f"[ARP:{op_status}] " f"SRC: {src_mac:<17} ({src_ip:<15}) " f"-> DST: {dst_mac:<17} ({dst_ip:<15})")

            # Track MAC-IP mapping for duplicate detection
            if is_private_ip(src_ip) and not is_multicast_or_broadcast_mac(src_mac):
                if src_ip in ip_mac_map:
                    if ip_mac_map[src_ip] != src_mac and is_private_ip(src_ip):
                        alert = f"[ALERT - POTENTIAL MAC SPOOFING] IP{src_ip} seen on multiple MAC Addresses: {ip_mac_map[src_ip]} and {src_mac} at {timestamp}"
                        log_alert(alert)
                else:
                    ip_mac_map[src_ip] = src_mac

                # Unknown device detection
                if src_mac not in whitelist: #and src_mac not in logged_alerts:
                    alert = f"[ALERT - UNKNOWN DEVICE] New MAC detected: {src_mac} ({src_ip}) at {timestamp}"
                    log_alert(alert)

                # Suspicious vendor detection
                mac_prefix = src_mac.upper()[0:8]
                if mac_prefix not in KNOWN_OUIS and src_mac not in whitelist and src_mac not in logged_alerts:
                    alert = f"[ALERT - SUSPICIOUS VENDOR] MAC prefix {mac_prefix} not recognized for {src_mac} ({src_ip}) at {timestamp}"
                    log_alert(alert)
                    logged_alerts.add(src_mac)

        elif pkt.haslayer(Ether) and pkt.haslayer(IP):
            src_mac = pkt[Ether].src
            dst_mac = pkt[Ether].dst
            src_ip  = pkt[IP].src
            dst_ip  = pkt[IP].dst
            op_status = "IP"
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            with open(OBSERVED_PACKET_LOG_FILE, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([timestamp, src_mac, dst_mac, src_ip, dst_ip])
            if (
                is_private_ip(src_ip) and is_private_ip(dst_ip) and
                not is_multicast_or_broadcast_mac(src_mac) and
                not is_multicast_or_broadcast_mac(dst_mac) and
                not is_multicast_ip(src_ip) and
                not is_multicast_ip(dst_ip)
            ):
                print(f"[{timestamp}] [ETH:{op_status}] SRC: {src_mac:<17} ({src_ip:<15}) -> DST: {dst_mac:<17} ({dst_ip:<15})")

            # Track MAC-IP mapping for duplicate detection
            if is_private_ip(src_ip) and not is_multicast_or_broadcast_mac(src_mac) and not is_multicast_ip(src_ip):
                if src_ip in ip_mac_map:
                    if ip_mac_map[src_ip] != src_mac and is_private_ip(src_ip):
                        alert = f"[ALERT - POTENTIAL MAC SPOOFING] IP{src_ip} seen on multiple MAC Addresses: {ip_mac_map[src_ip]} and {src_mac} at {timestamp}"
                        log_alert(alert)
                else:
                    ip_mac_map[src_ip] = src_mac

                # Unknown device detection
                if src_mac not in whitelist:
                    alert = f"[ALERT - UNKNOWN DEVICE] New MAC detected: {src_mac} ({src_ip}) at {timestamp}"
                    log_alert(alert)

                # Suspicious vendor detection
                mac_prefix = src_mac.upper()[0:8]
                if mac_prefix not in KNOWN_OUIS and src_mac not in whitelist and src_mac not in logged_alerts:
                    alert = f"[ALERT - SUSPICIOUS VENDOR] MAC prefix {mac_prefix} not recognized for {src_mac} ({src_ip}) at {timestamp}"
                    log_alert(alert)
                    logged_alerts.add(src_mac)

    sniff(prn=detect, store=0, filter="arp or (ip and not icmp)")

log_lock = threading.Lock()
def log_alert(message):
    with log_lock:
        print(f"    {message}", flush=True)
        with open(ALERT_LOG_FILE, "a") as f:
            f.write(message + "\n")

# === WHITELIST REVIEW / EDIT ===
def _normalize_mac(mac: str) -> str:
    return mac.strip().lower()

def _valid_mac(mac: str) -> bool:
    m = mac.strip().lower()
    parts = m.split(":")
    if len(parts) != 6:
        return False
    try:
        return all(len(p) == 2 and int(p, 16) >= 0 for p in parts)
    except ValueError:
        return False

def _print_whitelist():
    if not whitelist:
        print("\n[WHITELIST] (empty)")
        return
    print("\n[WHITELIST] Authorized devices:")
    for i, (mac, ip) in enumerate(sorted(whitelist.items()), start=1):
        print(f"  {i:2d}. {mac}  ->  {ip}")

def review_and_edit_whitelist():
    while True:
        _print_whitelist()
        print("\nOptions: [A]dd  [R]emove  [C]ontinue to detection")
        choice = input("Choose an option (A/R/C): ").strip().lower()

        if choice == "a":
            mac = input("  Enter MAC to add (format xx:xx:xx:xx:xx:xx): ").strip()
            if not _valid_mac(mac):
                print("  [!] Invalid MAC format. Try again.")
                continue
            mac = _normalize_mac(mac)
            ip = input("  Enter last-seen IP for this MAC (or press Enter to leave blank): ").strip()
            ip = ip if ip else "unknown"
            whitelist[mac] = ip # Dictionary update naturally prevents duplicates
            print(f"  [+] Added {mac} -> {ip}")

        elif choice == "r":
            key = input("  Enter MAC or list number to remove: ").strip().lower()
            removed = False
            if key.isdigit():
                idx = int(key)
                items = sorted(list(whitelist.items()))
                if 1 <= idx <= len(items):
                    mac_to_remove = items[idx - 1][0]
                    whitelist.pop(mac_to_remove, None)
                    print(f"  [-] Removed {mac_to_remove}")
                    removed = True
            if not removed:
                mac = _normalize_mac(key)
                if mac in whitelist:
                    whitelist.pop(mac, None)
                    print(f"  [-] Removed {mac}")
                else:
                    print("  [!] Not found in whitelist.")

        elif choice == "c":
            # FIXED: Change from "a" (append) to "w" (write/overwrite) to ensure a single, valid JSON object is saved.
            with open(WHITELIST_FILE, "w") as f:
                json.dump(whitelist, f, indent=4)
            print(f"\n[INFO] Whitelist saved to {WHITELIST_FILE}")
            confirm = input("Proceed to detection mode? (y/n): ").strip().lower()
            if confirm == "y":
                return True
            else:
                print("Okay, you can continue editing.")
        else:
            print("  [!] Invalid option. Please choose A, R, or C.")

# === MAIN EXECUTION ===
if __name__ == "__main__":
    print("=== MAC Address Anomaly Detector ===")
    print("1. Setup Mode (Collect MACs)")
    print("2. Detection Mode (Monitor Network)\n")

    if os.path.exists(WHITELIST_FILE) and os.path.getsize(WHITELIST_FILE) > 0:
        try:
            with open(WHITELIST_FILE, "r") as f:
                whitelist.update(json.load(f))
            print(f"[INFO] Loaded {len(whitelist)} existing whitelisted device(s).")
        except json.JSONDecodeError:
            print(f"[WARNING] Could not decode existing {WHITELIST_FILE}. Starting with an empty whitelist.")
        except Exception as e:
            print(f"[ERROR] Could not load initial whitelist: {e}. Starting with an empty whitelist.")

    setup_mode()

    review_and_edit_whitelist()

    try:
        detection_mode()
    except KeyboardInterrupt:
        print("\n[EXIT] Detection stopped by user.")
    finally:
        print(f"\n[INFO] Alerts saved in {ALERT_LOG_FILE}")
        print(f"[INFO] Packet logs saved in {OBSERVED_PACKET_LOG_FILE}")
        print(f"[INFO] Whitelist saved in {WHITELIST_FILE}")