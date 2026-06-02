import requests, json, os, time
from datetime import datetime

AWS_URL    = "https://aegis-ids-production.up.railway.app/ingest"
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
            from datetime import datetime
            all_traffic = json.load(open(TRAFFIC))
            now_str = datetime.now().strftime("%H:%M")
            traffic = [t for t in all_traffic if t.get("time","")[:5] >= now_str[:3]+"00"][-20:]
            if not traffic:
                traffic = all_traffic[-5:]

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
