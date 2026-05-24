import requests, json, os, time
from datetime import datetime

AWS_URL    = "http://13.51.158.81:5000/ingest"
SECRET     = "aegis-sync-secret-2026"
ALERTS     = "logs/alerts.txt"
TRAFFIC    = "logs/live_traffic.json"

def sync():
    try:
        alerts = []
        if os.path.exists(ALERTS):
            for line in open(ALERTS):
                line = line.strip()
                if "[BLOCKED]" in line:
                    parts = line.split("[BLOCKED]")
                    t = parts[0].strip()
                    rest = parts[1].strip() if len(parts) > 1 else ""
                    ip_r = rest.split("Reason:")
                    ip = ip_r[0].strip()
                    reason = ip_r[1].strip() if len(ip_r) > 1 else "Unknown"
                    alerts.append({"time": t, "ip": ip, "reason": reason})

        traffic = []
        if os.path.exists(TRAFFIC):
            traffic = json.load(open(TRAFFIC))

        payload = {
            "secret": SECRET,
            "alerts": alerts,
            "traffic": traffic,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

        r = requests.post(AWS_URL, json=payload, timeout=5)
        print("[SYNC] " + datetime.now().strftime("%H:%M:%S") + " status=" + str(r.status_code) + " alerts=" + str(len(alerts)) + " traffic=" + str(len(traffic)))
    except Exception as e:
        print("[SYNC ERROR] " + str(e))

while True:
    sync()
    time.sleep(3)
