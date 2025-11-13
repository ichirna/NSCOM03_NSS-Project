# MAC Address Anomaly Detector

This project is a simple LAN monitoring tool that uses **Scapy** to sniff packets and detect anomalies in MAC address usage.

It works in two main phases:

1. **Setup Mode** – learns the devices on your local network and builds a whitelist of MAC addresses, vendors, and their IPs.
2. **Detection Mode** – continuously monitors traffic and raises alerts for:
   - **Unknown devices** (MAC not in whitelist)
   - **Potential MAC spoofing** (same IP seen with multiple MAC addresses)
   - **Unknown vendors** (MAC OUI not found in the OUI database)

All alerts and observed packets are logged to files for later analysis.

---

## Requirements

- Python 3.x
- `scapy` library
- Run with enough privileges to capture packets:
  - On macOS / Linux: usually `sudo`

Install Scapy:

```bash
pip install scapy
