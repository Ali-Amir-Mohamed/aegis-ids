#!/bin/bash
cd ~/IDS_Project
sudo iptables -F
sudo chown -R amir-ali:amir-ali logs/ 2>/dev/null
echo "[]" > logs/live_traffic.json
echo "" > logs/alerts.txt
python3 dashboard.py &
echo "[OK] Dashboard at http://localhost:5000"
sleep 2
python3 ids_cloud_sync.py &
echo "[OK] Cloud sync started"
sleep 2
echo "[OK] Starting IDS..."
sudo python3 ids_realtime.py
