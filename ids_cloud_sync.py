import requests
import json
import os
import time
from datetime import datetime

RENDER_URL = "https://aegis-ids.onrender.com/ingest"
RENDER_HOME = "https://aegis-ids.onrender.com/"
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
        r = requests.post(RENDER_URL, json=data, timeout=15)
        now = datetime.now().strftime("%H:%M:%S")
        print("[SYNC] " + now + " status=" + str(r.status_code) + " alerts=" + str(len(alerts)) + " traffic=" + str(len(traffic)))
    except Exception as e:
        print("[SYNC ERROR] " + str(e))

def ping():
    try:
        requests.get(RENDER_HOME, timeout=10)
    except:
        pass

print("Cloud sync started - syncing every 25 seconds")
counter = 0
while True:
    sync()
    counter += 1
    time.sleep(25)
