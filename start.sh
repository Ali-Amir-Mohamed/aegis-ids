#!/bin/bash
cd ~/IDS_Project
sudo iptables -F
echo "[]" > logs/live_traffic.json
python3 dashboard.py &
sleep 2
sudo python3 ids_realtime.py
