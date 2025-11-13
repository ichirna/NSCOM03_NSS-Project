from scapy.all import sniff, ARP, Ether, IP
import json
import csv
import os
import threading
from datetime import datetime
import ipaddress
import re

"""
MAC Address Anomaly Detector

- Setup mode:
    * Sniffs ARP/IP packets for a fixed duration.
    * Learns devices on the LAN and stores them in a whitelist (MAC -> vendor + list of IPs).
- Detection mode:
    * Continuously sniffs ARP/IP packets.
    * Logs all observed packets to a CSV.
    * Detects anomalies:
        - Unknown devices (MAC not in whitelist).
        - Potential MAC spoofing (same IP used by multiple MAC addresses).
        - Unknown vendors (no matching OUI in the OUI database).
    * Writes alerts to a log file.
"""

# Seconds to stay in setup mode snifing for devices
SETUP_DURATION = 60

# File paths for persistent data/logs
WHITELIST_FILE = "whitelist.json"
ALERT_LOG_FILE = "alerts.txt"
OBSERVED_PACKET_LOG_FILE = "observed_packets.csv"

# In-memory state
whitelist = {}
logged_alerts = set()
ip_mac_map = { }

# OUI database
OUI_FILE = "oui.csv"
oui_vendors = {}
has_oui_db = False

def load_oui_vendors():
    """
    Load OUI -> vendor mappings from oui.csv into oui_vendors.

    Expected CSV columns:
        - "Assignment": first 3 bytes of MAC (e.g. "F8-A2-D6").
        - "Organization Name": vendor name.
    """
    global oui_vendors, has_oui_db
    if not os.path.exists(OUI_FILE):
        print(f"[WARNING] {OUI_FILE} not found. Vendor lookup disabled.")
        has_oui_db = False
        return

    try:
        with open(OUI_FILE, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                raw = (row.get("Assignment", "") or "").strip().upper()
                hexes = re.sub(r"[^0-9A-F]", "", raw)
                if len(hexes) != 6:
                    continue
                oui = ":".join(hexes[i:i+2] for i in range(0, 6, 2))
                vendor = (row.get("Organization Name", "") or "").strip()
                if vendor:
                    oui_vendors[oui] = vendor

        has_oui_db = len(oui_vendors) > 0
        print(f"[INFO] Loaded {len(oui_vendors)} vendor OUIs from {OUI_FILE}.")
    except Exception as e:
        has_oui_db = False
        print(f"[ERROR] Failed to load {OUI_FILE}: {e}")

def norm_mac(mac: str) -> str:
    """
    Normalize any MAC string into lowercase 'aa:bb:cc:dd:ee:ff' form.
    Returns '' if the input is invalid.

    This makes comparisons consistent even if Scapy or OS prints MACs differently.
    """
    if not mac:
        return ""
    hexes = re.sub(r'[^0-9A-Fa-f]', '', mac)
    if len(hexes) != 12:
        return ""
    return ":".join(hexes[i:i+2] for i in range(0, 12, 2)).lower()

def mac_oui(mac: str) -> str:
    """
    Extract the OUI (first 3 bytes) from a MAC address and return as 'F8:A2:D6'.
    Returns '' if MAC is invalid.
    """
    m = norm_mac(mac)
    if not m:
        return ""
    return m[:8].upper()

# === FILTERING HELPERS ===
def is_private_ip(ip_str: str) -> bool:
    """
    Return True if the IP string is a private address.
    We only care about private LAN traffic for this detector.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except Exception:
        return False

def is_multicast_ip(ip_str: str) -> bool:
    """
    Return True if IP string is a multicast address.
    Multicast addresses are ignored for anomaly detection.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_multicast
    except Exception:
        return False

def is_multicast_or_broadcast_mac(mac: str) -> bool:
    """
    Return True if the MAC is broadcast or a known multicast MAC prefix.
    These are excluded from whitelist and spoofing detection.
    """
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
    """
    Setup mode:
    - Sniff for a fixed duration.
    - Learn devices from ARP and non-ICMP IP traffic.
    - Merge (MAC -> {ips, vendor}) into the whitelist.
    """
    print(f"[SETUP MODE] Gathering MAC addresses for {SETUP_DURATION} seconds...")
    captured_devices = {}

    def collect_macs(pkt):
        """
        Packet handler for setup mode.
        Extracts MAC + IP from ARP or IP packets and stores them in captured_devices.
        """
        mac, ip = None, None

        # ARP
        if pkt.haslayer(ARP) and pkt[ARP].op in (1, 2):
            mac = pkt[ARP].hwsrc
            ip = pkt[ARP].psrc
            
        # IP over Ethernet
        elif pkt.haslayer(Ether) and pkt.haslayer(IP):
            mac = pkt[Ether].src
            ip  = pkt[IP].src
        else:
            return # ignore

        if not mac or is_multicast_or_broadcast_mac(mac):
            return
        if not is_private_ip(ip):
            return

        if mac not in captured_devices:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            captured_devices[mac] = ip
            print(f"[{timestamp}] [NEW DEVICE] MAC: {mac} | IP: {ip}")

    # Sniff packets for the setup duration
    sniff(prn=collect_macs, store=0, timeout=SETUP_DURATION,
          filter="arp or (ip and not icmp)")

    print(f"[SETUP COMPLETE] {len(captured_devices)} devices detected.")

    # MERGE INTO WHITELIST
    global whitelist
    added_count = 0
    updated_count = 0

    for mac, ip in captured_devices.items():
        nm = norm_mac(mac)
        if not nm:
            continue

        vendor = oui_vendors.get(mac_oui(nm), "Unknown")

        if nm not in whitelist:
            # Brand-new device
            whitelist[nm] = {
                "ips": [ip],
                "vendor": vendor,
            }
            added_count += 1
        else:
            # Already in whitelist, refresh IP list and vendor if needed
            meta = whitelist[nm]

            if isinstance(meta, dict):
                # Ensure we have an "ips" list
                if "ips" not in meta:
                    old_ip = meta.get("ip")
                    meta["ips"] = []
                    if old_ip and old_ip != "unknown":
                        meta["ips"].append(old_ip)
                    if "ip" in meta:
                        del meta["ip"]

                # Now meta["ips"] definitely exists
                if ip not in meta["ips"]:
                    meta["ips"].append(ip)
                    updated_count += 1

                # Upgrade vendor if it was unknown before
                if meta.get("vendor", "Unknown") == "Unknown" and vendor != "Unknown":
                    meta["vendor"] = vendor

    # Save updated whitelist
    with open(WHITELIST_FILE, "w") as f:
        json.dump(whitelist, f, indent=4)

    print(f"[INFO] {added_count} new device(s) added to whitelist, {updated_count} updated.")
    print(f"[INFO] Total whitelist size: {len(whitelist)}")

# === DETECTION MODE ===
def detection_mode():
    """
    Detection mode:
    - Sniffs ARP and non-ICMP IP packets continuously.
    - Logs all observed packets to CSV.
    - Generates alerts for:
        * Potential MAC spoofing (same IP -> multiple MACs).
        * Unknown devices (MAC not in whitelist).
        * Unknown vendors (no matching OUI in DB).
    """
    print("\n[DETECTION MODE] Monitoring for anomalies (Press Ctrl + C to stop)...")
    
    # Resets alerts file at the start of each run
    open(ALERT_LOG_FILE, "w").close()
    
    # Initialize observed packets CSV
    if not os.path.exists(OBSERVED_PACKET_LOG_FILE):
        with open(OBSERVED_PACKET_LOG_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Source MAC", "Destination MAC", "Source IP", "Destination IP"])

    def detect(pkt):
        """
        Packet handler for detection mode.
        Processes ARP and IP packets and performs:
        - Logging
        - Spoofing checks
        - Unknown device/vendor detection
        """
        # ARP Packet
        if pkt.haslayer(ARP):
            src_mac_raw = pkt[ARP].hwsrc
            dst_mac_raw = pkt[ARP].hwdst
            src_mac = norm_mac(src_mac_raw)
            dst_mac = norm_mac(dst_mac_raw)
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
            if src_mac and is_private_ip(src_ip) and not is_multicast_or_broadcast_mac(src_mac):
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
                else:
                    entry = whitelist[src_mac]

                    # Case 1: New format already uses "ips"
                    if "ips" in entry:
                        if src_ip not in entry["ips"]:
                            entry["ips"].append(src_ip)

                    # Case 2: Old format: "ip": "something"
                    else:
                        old_ip = entry.get("ip")
                        entry["ips"] = []
                        if old_ip and old_ip != "unknown":
                            entry["ips"].append(old_ip)
                        if src_ip not in entry["ips"]:
                            entry["ips"].append(src_ip)

                        # Remove old "ip" key to avoid confusion
                        if "ip" in entry:
                            del entry["ip"]

                # Suspicious vendor detection
                if has_oui_db:
                    vendor = oui_vendors.get(mac_oui(src_mac))
                    if not vendor and src_mac not in whitelist and src_mac not in logged_alerts:
                        alert = f"[ALERT - UNKNOWN VENDOR] No OUI match for {src_mac} ({src_ip}) at {timestamp}"
                        log_alert(alert)
                        logged_alerts.add(src_mac)

        # IP over Ethernet Packet
        elif pkt.haslayer(Ether) and pkt.haslayer(IP):
            src_mac_raw = pkt[Ether].src
            dst_mac_raw = pkt[Ether].dst
            src_mac = norm_mac(src_mac_raw)
            dst_mac = norm_mac(dst_mac_raw)
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
                if has_oui_db:
                    vendor = oui_vendors.get(mac_oui(src_mac))
                    if not vendor and src_mac not in whitelist and src_mac not in logged_alerts:
                        alert = f"[ALERT - UNKNOWN VENDOR] No OUI match for {src_mac} ({src_ip}) at {timestamp}"
                        log_alert(alert)
                        logged_alerts.add(src_mac)

    sniff(prn=detect, store=0, filter="arp or (ip and not icmp)")

log_lock = threading.Lock()

def log_alert(message):
    """
    Print an alert to the console and append it to ALERT_LOG_FILE.
    Protected by a lock so multiple alerts don't interleave writes.
    """
    with log_lock:
        print(f"    {message}", flush=True)
        with open(ALERT_LOG_FILE, "a") as f:
            f.write(message + "\n")

# === WHITELIST REVIEW / EDIT ===
def _valid_mac(mac: str) -> bool:
    """
    Basic syntax checker for MAC addresses entered by the user.
    Only checks format 'xx:xx:xx:xx:xx:xx' and hex validity.
    """
    m = mac.strip().lower()
    parts = m.split(":")
    if len(parts) != 6:
        return False
    try:
        return all(len(p) == 2 and int(p, 16) >= 0 for p in parts)
    except ValueError:
        return False

def _print_whitelist():
    """
    Pretty-print the current whitelist to the console.
    Handles both old format ("ip") and new format ("ips").
    """
    if not whitelist:
        print("\n[WHITELIST] (empty)")
        return
    print("\n[WHITELIST] Authorized devices:")
    for i, (mac, meta) in enumerate(sorted(whitelist.items()), start=1):
        if isinstance(meta, dict):
            # Prefer "ips" list if present
            if "ips" in meta:
                ips = meta.get("ips", [])
                ip_display = ", ".join(ips) if ips else "unknown"
            else:
                ip_display = meta.get("ip", "unknown")
            vendor = meta.get("vendor", "Unknown")
        else:
            ip_display = str(meta)
            vendor = "Unknown"
        print(f"  {i:2d}. {mac}  ->  {ip_display}  ({vendor})")

def review_and_edit_whitelist():
    """
    Simple interactive CLI to:
        - Add MACs to whitelist.
        - Remove MACs by address or index.
        - Save and continue to detection mode.
    """
    while True:
        _print_whitelist()
        print("\nOptions: [A]dd  [R]emove  [C]ontinue to detection")
        choice = input("Choose an option (A/R/C): ").strip().lower()

        if choice == "a":
            mac = input("  Enter MAC to add (format xx:xx:xx:xx:xx:xx): ").strip()
            if not _valid_mac(mac):
                print("  [!] Invalid MAC format. Try again.")
                continue
            mac = norm_mac(mac)
            ip = input("  Enter last-seen IP for this MAC (or press Enter to leave blank): ").strip()
            ip = ip if ip else "unknown"
            vendor = oui_vendors.get(mac_oui(mac), "Unknown") if has_oui_db else "Unknown"
            whitelist[mac] = {"ip": ip, "vendor": vendor}

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
                mac = norm_mac(key)
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
    load_oui_vendors()
    print("1. Setup Mode (Collect MACs)")
    print("2. Detection Mode (Monitor Network)\n")

    # Load existing whitelist if available
    if os.path.exists(WHITELIST_FILE) and os.path.getsize(WHITELIST_FILE) > 0:
        try:
            with open(WHITELIST_FILE, "r") as f:
                whitelist.update(json.load(f))
            print(f"[INFO] Loaded {len(whitelist)} existing whitelisted device(s).")

            # MIGRATE LEGACY FORMAT IF NEEDED
            migrated = 0
            for mac, meta in list(whitelist.items()):
                if isinstance(meta, dict) and "ip" in meta and "ips" not in meta:
                    ip = meta["ip"]
                    meta["ips"] = []
                    if ip and ip != "unknown":
                        meta["ips"].append(ip)
                    del meta["ip"]
                    migrated += 1

            if migrated:
                print(f"[INFO] Migrated {migrated} legacy whitelist entrie(s) to new schema.")

        except json.JSONDecodeError:
            print(f"[WARNING] Could not decode existing {WHITELIST_FILE}. Starting with an empty whitelist.")
            whitelist = {}
        except Exception as e:
            print(f"[ERROR] Could not load initial whitelist: {e}. Starting with an empty whitelist.")
            whitelist = {}
            
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