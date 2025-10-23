
import csv
import json
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from scapy.all import sniff, ARP, Ether, IP

USE_LOCAL_MAC_DB = False
try:
    from mac_vendor_lookup import MacLookup
    mac_lookup_local = MacLookup()
    USE_LOCAL_MAC_DB = True
except Exception:
    mac_lookup_local = None

# HTTP lookup
import requests
MACVENDORS_API = "https://api.macvendors.com/{}"  

# Config
ALERT_LOG_FILE = "mac_alerts.log"
OBSERVATION_CSV = "mac_observations.csv"
STATE_DUMP_JSON = "mac_state.json"

# Detection thresholds
MULTI_IP_WINDOW = timedelta(seconds=30)   
MULTI_IP_COUNT = 2                        
MAC_CHURN_WINDOW = timedelta(seconds=60)  
MAC_CHURN_THRESHOLD = 4                  

# Data stores in memory
mac_history = defaultdict(lambda: deque(maxlen=2000))
ip_history = defaultdict(lambda: deque(maxlen=2000))

# CSV
csv_lock = threading.Lock()
with open(OBSERVATION_CSV, "a", newline='') as _f:
    writer = csv.writer(_f)
    writer.writerow(["timestamp", "mac", "ip", "iface", "vendor", "note"])


def now_ts():
    return datetime.now().isoformat() + "Z"


def lookup_vendor(mac):
    if USE_LOCAL_MAC_DB:
        try:
            v = mac_lookup_local.lookup(mac)
            return v
        except Exception:
            pass
    try:
        r = requests.get(MACVENDORS_API.format(mac), timeout=3)
        if r.status_code == 200:
            txt = r.text.strip()
            return txt if txt else "Unknown"
    except Exception:
        pass
    return "Unknown"


def is_locally_administered(mac):
    try:
        b = int(mac.split(":")[0], 16)
        return bool(b & 0x02)
    except Exception:
        return False


def is_multicast_mac(mac):
    try:
        b = int(mac.split(":")[0], 16)
        return bool(b & 0x01)
    except Exception:
        return False


def log_observation(mac, ip, iface, vendor, note=""):
    ts = now_ts()
    with csv_lock:
        with open(OBSERVATION_CSV, "a", newline='') as f:
            writer = csv.writer(f)
            writer.writerow([ts, mac, ip or "", iface or "", vendor or "", note or ""])


def write_alert(message):
    ts = now_ts()
    line = f"[ALERT] {ts} - {message}"
    print(line)
    with open(ALERT_LOG_FILE, "a") as f:
        f.write(line + "\n")


def record_and_check(mac, ip=None, iface=None):
    t = datetime.now()
    mac_history[mac].append((t, ip, iface))
    if ip:
        ip_history[ip].append((t, mac))
    vendor = lookup_vendor(mac)

    log_observation(mac, ip, iface, vendor, note="observed")

    if is_locally_administered(mac):
        write_alert(f"Locally administered MAC detected: {mac} (vendor={vendor})")

    if is_multicast_mac(mac):
        write_alert(f"Multicast MAC detected: {mac} (vendor={vendor})")

    # same MAC seen with multiple IPs in short window?
    cutoff = t - MULTI_IP_WINDOW
    ips = set()
    for ts, rec_ip, rec_iface in mac_history[mac]:
        if ts >= cutoff and rec_ip:
            ips.add(rec_ip)
    if len(ips) >= MULTI_IP_COUNT:
        write_alert(f"MAC {mac} seen using multiple IPs within {MULTI_IP_WINDOW.total_seconds()}s: {sorted(ips)} (vendor={vendor})")

    # one ip having many different MACs
    if ip:
        cutoff_churn = t - MAC_CHURN_WINDOW
        macs_for_ip = set()
        for ts2, rec_mac in ip_history[ip]:
            if ts2 >= cutoff_churn:
                macs_for_ip.add(rec_mac)
        if len(macs_for_ip) >= MAC_CHURN_THRESHOLD:
            write_alert(f"High MAC churn for IP {ip}: saw {len(macs_for_ip)} different MACs in last {MAC_CHURN_WINDOW.total_seconds()}s -> {sorted(macs_for_ip)}")

    # suspicious vendor
    if vendor == "Unknown":
        write_alert(f"Unknown vendor for MAC {mac}. Vendor lookup failed or not found.")


def packet_handler(pkt):
    try:
        if ARP in pkt and pkt[ARP].op in (1,2): 
            mac = pkt[ARP].hwsrc.lower()
            ip = pkt[ARP].psrc
            iface = pkt.sniffed_on if hasattr(pkt, "sniffed_on") else None
            record_and_check(mac, ip, iface)
        elif IP in pkt:
            if pkt.haslayer(Ether):
                mac = pkt[Ether].src.lower()
                ip = pkt[IP].src
                iface = pkt.sniffed_on if hasattr(pkt, "sniffed_on") else None
                record_and_check(mac, ip, iface)
    except Exception as e:
        print(f"Error processing packet: {e}")


def periodic_state_dump(interval=300):
    try:
        summary = {}
        for mac, dq in mac_history.items():
            last_seen = dq[-1][0].isoformat() if dq else None
            ips = sorted({x[1] for x in dq if x[1]})
            summary[mac] = {"last_seen": last_seen, "ips": ips, "observations": len(dq)}
        with open(STATE_DUMP_JSON, "w") as f:
            json.dump({"generated": now_ts(), "summary": summary}, f, indent=2)
    except Exception as e:
        print(f"Periodic dump error: {e}")

    threading.Timer(interval, periodic_state_dump, kwargs={"interval": interval}).start()


def main():
    print("MAC Anomaly Detector starting. Press Ctrl-C to stop.")
    print("Using local mac DB:" , "yes" if USE_LOCAL_MAC_DB else "no (using API fallback)")
    periodic_state_dump(interval=300)
    sniff(prn=packet_handler, store=0, filter="arp or (ip and not icmp)") 


if __name__ == "__main__":
    main()
