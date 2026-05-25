import requests
import json
import os
import time
from datetime import datetime

AWS_URL = "http://13.51.158.81:5000/ingest"
SECRET = "aegis-sync-secret-2026"

def sync():
    try:
        alerts = []
        if os.path.exists("logs/alerts.txt"):
            for line in open("logs/alerts.txt"):
                line = line.strip()
                if "[BLOCKED]" in line and len(line) > 10:
                    parts = line.split("[BLOCKED]")
                    t = parts[0].strip()
                    rest = parts[1].strip() if len(parts)>1 else ""
                    ip_r = rest.split("Reason:")
                    ip = ip_r[0].strip()
                    reason = ip_r[1].strip() if len(ip_r)>1 else "Unknown"
                    if ip:
                        alerts.append({"ip":ip,"reason":reason,"time":t})
        traffic = []
        if os.path.exists("logs/live_traffic.json"):
            traffic = json.load(open("logs/live_traffic.json"))
        data = {
            "secret": SECRET,
            "alerts": alerts,
            "traffic": traffic[-20:],
            "timestamp": datetime.now().isoformat()
        }
        r = requests.post(AWS_URL, json=data, timeout=5)
        print("[SYNC] " + datetime.now().strftime("%H:%M:%S") + " status=" + str(r.status_code) + " alerts=" + str(len(alerts)) + " traffic=" + str(len(traffic)) + " response=" + r.text)
    except Exception as e:
        print("[SYNC ERROR] " + str(e))

print("Real-time sync started - every 3 seconds")
while True:
    sync()
    time.sleep(3)
