# AEGIS — AI-Enhanced Guardian for Intrusion Surveillance

> A real-time, machine-learning-powered Intrusion Detection and Prevention System (IDS/IPS) with automatic threat blocking and a live web dashboard.

**Author:** Amir Ali
**Project:** Bachelor Degree in Cybersecurity
**Repository:** https://github.com/Ali-Amir-Mohamed/aegis-ids

---

## Overview

AEGIS is a real-time intrusion detection and prevention system that monitors network traffic, detects attacks using a combination of signature-based inspection, behavioral analysis, and a machine learning model, and automatically blocks malicious IP addresses via the system firewall (iptables).

The name **AEGIS** stands for **AI-Enhanced Guardian for Intrusion Surveillance**, a reference to the mythological shield of protection.

## Key Features

- **Real-time detection & blocking** — attacks are detected and the source IP is blocked via iptables in seconds
- **Machine Learning engine** — Random Forest classifier (99.88% accuracy, trained on CIC-IDS2017)
- **Hybrid detection** — combines payload signatures, behavioral thresholds, and ML prediction
- **Live web dashboard** — real-time stats, alerts, blocked IPs, and traffic split
- **Cloud dashboard** — accessible from anywhere (including mobile) via Railway deployment
- **Email alerts** — automatic notification on each detected attack
- **Audio alerts** — sound notification in the dashboard when an attack occurs
- **IP geolocation** — identifies the country/city of external attackers
- **Runs as a system service** — starts automatically at boot, self-restarts on failure

## Detected Attacks

AEGIS detects and blocks the following attacks in real time:

| # | Attack | Detection method |
|---|--------|------------------|
| 1 | SSH Brute Force | Behavioral (port 22 connection rate) |
| 2 | FTP Brute Force | Behavioral (port 21 connection rate) |
| 3 | SYN Flood | Behavioral (SYN packet rate) |
| 4 | Port Scan | Behavioral (distinct ports targeted) |
| 5 | HTTP Flood / DoS | Behavioral (request rate) |
| 6 | Nikto Web Scan | Payload signature |
| 7 | SQL Injection | Payload signature |
| 8 | DoS GoldenEye | Behavioral / signature |
| 9 | DoS Slowloris | Behavioral / signature |
| 10 | XSS (Cross-Site Scripting) | Payload signature |
| 11 | Slowhttptest (Slow DoS) | Behavioral |
| 12 | DDoS (volumetric flood) | Behavioral |

The ML model additionally covers **Botnet**, **Heartbleed**, and **Infiltration** (trained on CIC-IDS2017 data).

## Architecture

AEGIS uses a three-layer client-server architecture:

1. **Detection Agent** (`ids_realtime.py`) — runs on the protected machine; captures traffic, runs detection, blocks threats via iptables
2. **Cloud Sync** (`ids_sync.py`) — forwards alerts and traffic data to the cloud dashboard
3. **Dashboard** (`dashboard.py`) — Flask web app, available locally and on the cloud (Railway)

## Technologies

- **Python 3** — core language
- **Scapy** — packet capture and analysis
- **scikit-learn** — Random Forest ML model
- **Flask** — web dashboard
- **iptables** — automatic IP blocking
- **Railway** — cloud deployment
- **CIC-IDS2017** — training dataset
- **systemd** — background service management

## Installation

### Requirements
- A Linux machine (Ubuntu recommended)
- Python 3.x
- Root privileges (for packet capture and iptables)

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/Ali-Amir-Mohamed/aegis-ids.git
cd aegis-ids

# 2. Install dependencies
pip install -r requirements.txt --break-system-packages

# 3. Configure for your machine (see Configuration below)

# 4. Run the system
sudo python3 ids_realtime.py &
python3 dashboard.py &
python3 ids_sync.py &
```

Then open `http://localhost:5000` (default login: `admin` / `aegis123`).

### Deploying on another machine

AEGIS is portable to any Linux machine. After cloning and installing dependencies, adapt two machine-specific parameters in `ids_realtime.py`:
- **Network interfaces** — update the `iface=[...]` list in the `sniff()` call to match your machine's interfaces (check with `ip a`)
- **Local IP whitelist** — update the IP addresses excluded from detection to match your machine's local IPs

## Running as a Background Service (systemd)

AEGIS can run automatically in the background using systemd services (`aegis-realtime`, `aegis-dashboard`, `aegis-sync`):

```bash
# Start
sudo systemctl start aegis-realtime aegis-dashboard aegis-sync

# Enable at boot
sudo systemctl enable aegis-realtime aegis-dashboard aegis-sync

# View live logs
sudo journalctl -u aegis-realtime -f

# Restart after a code change
sudo systemctl restart aegis-realtime
```

## Limitations & Future Work

- **Single-machine monitoring** — the current version monitors one machine. Multi-machine support (per-device dashboards) is a planned evolution: it would require adding a machine identifier to each alert and filtering the dashboard per machine.
- **Linux only** — relies on iptables and Scapy.
- **Cloud dashboard latency** — the cloud dashboard updates with a few seconds delay (HTTP sync).

## License

Academic project — Bachelor Degree in Cybersecurity.
