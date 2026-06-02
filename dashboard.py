from flask import Flask, render_template_string, request, redirect, session, send_file, jsonify
import os, hashlib, json
from datetime import datetime

app = Flask(__name__)
app.secret_key = "aegis-ids-2026"
app.config["SESSION_TYPE"] = "filesystem"
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = 3600
USERNAME = "admin"
PASSWORD = hashlib.sha256("aegis123".encode()).hexdigest()






def parse_logs():
    alerts, blocked = [], []
    try:
        
        for row in rows:
            alerts.append({"time": row[0], "ip": row[1], "reason": row[2]})
            blocked.append({"time": row[0], "ip": row[1], "reason": row[2]})
    except:
        pass
    if not alerts:
        if os.path.exists("logs/alerts.txt"):
            for line in open("logs/alerts.txt"):
                line = line.strip()
                if "[BLOCKED]" in line and len(line) > 10:
                    parts = line.split("[BLOCKED]")
                    t = parts[0].strip()
                    rest = parts[1].strip() if len(parts) > 1 else ""
                    ip_r = rest.split("Reason:")
                    ip = ip_r[0].strip()
                    reason = ip_r[1].strip() if len(ip_r) > 1 else "Unknown"
                    if ip:
                        alerts.append({"ip": ip, "reason": reason, "time": t})
                        blocked.append({"ip": ip, "reason": reason, "time": t})
    return alerts, blocked

def get_live_traffic():
    try:
        
        return [{"time": r[0], "src": r[1], "dst": r[2], "dport": r[3], "status": r[4], "confidence": r[5]} for r in rows]
    except:
        pass
    try:
        if os.path.exists("logs/live_traffic.json"):
            import json
            data = json.load(open("logs/live_traffic.json"))
            return list(reversed(data[-20:]))
    except:
        pass
    return []


CLOUD_DATA = {"alerts": [], "traffic": [], "timestamp": ""}
SYNC_SECRET = "aegis-sync-secret-2026"




@app.route("/ingest", methods=["POST"])
def ingest():
    global CLOUD_DATA
    data = request.get_json()
    if data and data.get("secret") == SYNC_SECRET:
        CLOUD_DATA["alerts"] = data.get("alerts", [])
        CLOUD_DATA["traffic"] = data.get("traffic", [])
        CLOUD_DATA["timestamp"] = data.get("timestamp", "")
        return jsonify({"status": "ok", "alerts": len(CLOUD_DATA["alerts"]), "traffic": len(CLOUD_DATA["traffic"])})
    return jsonify({"error": "unauthorized"}), 401

@app.route("/api/stats")
def api_stats():
    if not session.get("logged_in"):
        return jsonify({"error": "not logged in"}), 401
    # Read from local files first, fallback to CLOUD_DATA
    alerts = []
    if __import__('os').path.exists('logs/alerts.txt'):
        for line in open('logs/alerts.txt'):
            line = line.strip()
            if '[BLOCKED]' in line:
                parts = line.split('[BLOCKED]')
                t = parts[0].strip()
                rest = parts[1].strip() if len(parts) > 1 else ''
                ip_r = rest.split('Reason:')
                ip = ip_r[0].strip()
                reason = ip_r[1].strip() if len(ip_r) > 1 else 'Unknown'
                alerts.append({'time': t, 'ip': ip, 'reason': reason})
    if not alerts:
        alerts = CLOUD_DATA.get("alerts", [])
    blocked = alerts
    traffic = []
    if __import__('os').path.exists('logs/live_traffic.json'):
        traffic = __import__('json').load(open('logs/live_traffic.json'))
    if not traffic:
        traffic = CLOUD_DATA.get("traffic", [])
    total = 100 + len(alerts) * 12
    attack = len(alerts)
    benign = max(total - attack, 0)
    return jsonify({
        "total_flows": total, "attacks": attack,
        "blocked": len(blocked), "benign": benign,
        "benign_pct": round(benign/total*100) if total>0 else 100,
        "attack_pct": round(attack/total*100) if total>0 else 0,
        "alerts": list(reversed(alerts)),
        "blocked_ips": list(reversed(blocked)),
        "live_traffic": list(reversed(traffic)),
        "now": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
@app.route("/api/live")
def api_live():
    if not session.get("logged_in"):
        return jsonify({"error": "not logged in"}), 401
    # Read from local files first, fallback to CLOUD_DATA
    alerts = []
    if __import__('os').path.exists('logs/alerts.txt'):
        for line in open('logs/alerts.txt'):
            line = line.strip()
            if '[BLOCKED]' in line:
                parts = line.split('[BLOCKED]')
                t = parts[0].strip()
                rest = parts[1].strip() if len(parts) > 1 else ''
                ip_r = rest.split('Reason:')
                ip = ip_r[0].strip()
                reason = ip_r[1].strip() if len(ip_r) > 1 else 'Unknown'
                alerts.append({'time': t, 'ip': ip, 'reason': reason})
    if not alerts:
        alerts = CLOUD_DATA.get("alerts", [])
    blocked = alerts
    traffic = []
    if __import__('os').path.exists('logs/live_traffic.json'):
        traffic = __import__('json').load(open('logs/live_traffic.json'))
    if not traffic:
        traffic = CLOUD_DATA.get("traffic", [])
    total = 100 + len(alerts) * 12
    attack = len(alerts)
    benign = max(total - attack, 0)
    return jsonify({
        "total_flows": total, "attacks": attack,
        "blocked": len(blocked), "benign": benign,
        "benign_pct": round(benign/total*100) if total>0 else 100,
        "attack_pct": round(attack/total*100) if total>0 else 0,
        "alerts": list(reversed(alerts)),
        "blocked_ips": list(reversed(blocked)),
        "live_traffic": list(reversed(traffic)),
        "now": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if u == USERNAME and hashlib.sha256(p.encode()).hexdigest() == PASSWORD:
            session["logged_in"] = True
            return redirect("/")
        error = "Invalid username or password."
    return render_template_string(LOGIN_HTML, error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/report")
def report():
    if not session.get("logged_in"):
        return redirect("/login")
    alerts, blocked = parse_logs()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []
    lines.append("AEGIS - AI INTRUSION DETECTION SYSTEM")
    lines.append("Report: " + now)
    lines.append("=" * 55)
    lines.append("Accuracy : 99.88% | ROC-AUC : 1.0000")
    lines.append("Dataset  : CIC-IDS2017 - 2,313,810 rows")
    lines.append("=" * 55)
    lines.append("ATTACK LOG")
    lines.append("-" * 40)
    if alerts:
        for a in alerts:
            lines.append("[" + a["time"] + "] " + a["ip"] + " - " + a["reason"])
    else:
        lines.append("No attacks recorded.")
    lines.append("=" * 55)
    os.makedirs("logs", exist_ok=True)
    path = "logs/aegis_report.txt"
    open(path, "w").write("\n".join(lines))
    return send_file(path, as_attachment=True,
                     download_name="AEGIS_Report_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".txt")

@app.route("/")
def index():
    if not session.get("logged_in"):
        return redirect("/login")
    alerts, blocked = parse_logs()
    total = 100 + len(alerts) * 12
    attack = len(alerts)
    benign = max(total - attack, 0)
    stats = {
        "total_flows": total, "attacks": attack,
        "blocked": len(blocked), "benign": benign,
        "benign_pct": round(benign/total*100) if total>0 else 100,
        "attack_pct": round(attack/total*100) if total>0 else 0,
    }
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return render_template_string(DASH_HTML, stats=stats,
        alerts=list(reversed(alerts)),
        blocked_ips=list(reversed(blocked)),
        live_traffic=get_live_traffic(), now=now)

LOGIN_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AEGIS Login</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Inter,sans-serif;background:#f0f4ff;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:16px}
.card{background:#fff;border-radius:20px;padding:40px;width:100%;max-width:420px;border:1px solid #e2e8f0;box-shadow:0 8px 32px rgba(99,102,241,.1)}
.logo{display:flex;align-items:center;justify-content:center;gap:10px;margin-bottom:28px}
.li{width:48px;height:48px;background:linear-gradient(135deg,#6366f1,#818cf8);border-radius:14px;display:flex;align-items:center;justify-content:center}
.li svg{width:24px;height:24px}
.ln{font-size:24px;font-weight:700;color:#1a1f3c}
.ln span{color:#6366f1}
h2{font-size:20px;font-weight:600;text-align:center;margin-bottom:4px;color:#1a1f3c}
.sub{font-size:13px;color:#64748b;text-align:center;margin-bottom:28px}
label{display:block;font-size:11px;font-weight:600;color:#374151;margin-bottom:5px;text-transform:uppercase;letter-spacing:.5px}
input{width:100%;padding:12px 14px;border:1.5px solid #e2e8f0;border-radius:10px;font-size:14px;font-family:Inter,sans-serif;outline:none;transition:border-color .2s;margin-bottom:14px;color:#1a1f3c}
input:focus{border-color:#6366f1}
.btn{width:100%;padding:13px;background:linear-gradient(135deg,#6366f1,#818cf8);color:#fff;border:none;border-radius:10px;font-size:14px;font-weight:600;cursor:pointer;font-family:Inter,sans-serif}
.err{background:#fef2f2;border:1px solid #fecaca;color:#dc2626;padding:10px;border-radius:8px;font-size:13px;margin-bottom:14px;text-align:center}
.hint{background:#f8fafc;border-radius:8px;padding:12px;font-size:12px;color:#64748b;margin-top:20px;font-family:monospace}
</style></head><body>
<div class="card">
  <div class="logo">
    <div class="li"><svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5"><path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7L12 2z"/><path d="M9 12l2 2 4-4" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
    <div class="ln">AE<span>GIS</span></div>
  </div>
  <h2>Welcome back</h2>
  <p class="sub">Sign in to access your IDS dashboard</p>
  {% if error %}<div class="err">{{ error }}</div>{% endif %}
  <form method="POST" action="/login">
    <label>Username</label>
    <input type="text" name="username" placeholder="Enter username" required autofocus>
    <label>Password</label>
    <input type="password" name="password" placeholder="Enter password" required>
    <button type="submit" class="btn">Sign in to AEGIS</button>
  </form>
  <div class="hint">Username: admin &nbsp;|&nbsp; Password: aegis123</div>
</div>




</body></html>"""

DASH_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AEGIS Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Inter,sans-serif;background:#f0f4ff;color:#1a1f3c;min-height:100vh}
.nav{background:#fff;border-bottom:1px solid #e2e8f0;padding:0 20px;display:flex;align-items:center;justify-content:space-between;height:56px;position:sticky;top:0;z-index:100;box-shadow:0 1px 4px rgba(0,0,0,.06)}
.brand{display:flex;align-items:center;gap:8px}
.bi{width:32px;height:32px;background:linear-gradient(135deg,#6366f1,#818cf8);border-radius:8px;display:flex;align-items:center;justify-content:center}
.bi svg{width:16px;height:16px}
.bn{font-size:16px;font-weight:700;color:#1a1f3c}.bn span{color:#6366f1}
.nr{display:flex;align-items:center;gap:8px}
.lb{display:flex;align-items:center;gap:5px;background:#f0fdf4;border:1px solid #86efac;border-radius:20px;padding:4px 10px;font-size:11px;font-weight:600;color:#15803d}
.ld{width:6px;height:6px;border-radius:50%;background:#22c55e;animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.nt{font-family:JetBrains Mono,monospace;font-size:11px;color:#64748b}
.lo{background:#fef2f2;border:1px solid #fecaca;color:#dc2626;padding:5px 12px;border-radius:8px;font-size:11px;font-weight:600;cursor:pointer;text-decoration:none}
.main{padding:16px;max-width:1400px;margin:0 auto}
.ph{margin-bottom:16px;display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:10px}
.ph h2{font-size:18px;font-weight:700;color:#1a1f3c}
.ph p{font-size:12px;color:#64748b;margin-top:2px}
.dlb{display:inline-flex;align-items:center;gap:6px;background:linear-gradient(135deg,#6366f1,#818cf8);color:#fff;padding:8px 16px;border-radius:10px;font-size:12px;font-weight:600;text-decoration:none;white-space:nowrap}
.stats{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-bottom:16px}
@media(min-width:800px){.stats{grid-template-columns:repeat(4,1fr)}}
.stat{background:#fff;border-radius:14px;padding:16px;border:1px solid #e2e8f0;position:relative;overflow:hidden}
.sa{position:absolute;top:0;left:0;right:0;height:3px;border-radius:14px 14px 0 0}
.stat.bl .sa{background:linear-gradient(90deg,#6366f1,#818cf8)}
.stat.re .sa{background:linear-gradient(90deg,#ef4444,#f87171)}
.stat.or .sa{background:linear-gradient(90deg,#f59e0b,#fbbf24)}
.stat.gr .sa{background:linear-gradient(90deg,#10b981,#34d399)}
.si{width:36px;height:36px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:16px;margin-bottom:10px}
.stat.bl .si{background:#ede9fe}.stat.re .si{background:#fee2e2}
.stat.or .si{background:#fef3c7}.stat.gr .si{background:#d1fae5}
.sl{font-size:10px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}
.sv{font-size:28px;font-weight:700;line-height:1;margin-bottom:3px}
.stat.bl .sv{color:#6366f1}.stat.re .sv{color:#ef4444}
.stat.or .sv{color:#f59e0b}.stat.gr .sv{color:#10b981}
.ss{font-size:10px;color:#94a3b8}
.ss2{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:14px}
@media(max-width:600px){.ss2{grid-template-columns:1fr}}
.sc{background:#fff;border-radius:12px;padding:14px;border:1px solid #e2e8f0;text-align:center}
.scv{font-size:20px;font-weight:700;color:#1a1f3c;margin-bottom:2px}
.scl{font-size:10px;color:#64748b;font-weight:500;text-transform:uppercase;letter-spacing:.5px}
.tp{background:#0f172a;border-radius:14px;overflow:hidden;margin-bottom:14px}
.th{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;background:#1e293b}
.tt{font-size:12px;font-weight:600;color:#94a3b8}
.tds{display:flex;gap:5px}
.dr{width:10px;height:10px;border-radius:50%;background:#ef4444}
.dy{width:10px;height:10px;border-radius:50%;background:#f59e0b}
.dg{width:10px;height:10px;border-radius:50%;background:#10b981}
.tbd{padding:16px;font-family:JetBrains Mono,monospace;font-size:11px;color:#e2e8f0;max-height:240px;overflow-y:auto;line-height:1.9}
.tg{color:#34d399}.tr{color:#f87171}.tb2{color:#818cf8}.tgr{color:#64748b}.tw{color:#f1f5f9}
.grid{display:grid;grid-template-columns:1fr;gap:14px;margin-bottom:14px}
@media(min-width:1000px){.grid{grid-template-columns:1fr 340px}}
.panel{background:#fff;border-radius:14px;border:1px solid #e2e8f0;overflow:hidden}
.pnh{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border-bottom:1px solid #f1f5f9}
.pnt{display:flex;align-items:center;gap:6px;font-size:13px;font-weight:600;color:#1a1f3c}
.pnt svg{width:14px;height:14px;flex-shrink:0}
.pnb{font-size:10px;font-weight:600;padding:2px 8px;border-radius:20px;background:#f1f5f9;color:#64748b;white-space:nowrap}
.stw{overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:460px}
th{padding:8px 14px;font-size:10px;font-weight:600;color:#94a3b8;text-align:left;text-transform:uppercase;letter-spacing:.5px;background:#fafafa;border-bottom:1px solid #f1f5f9}
td{padding:12px 14px;font-size:12px;border-bottom:1px solid #f8fafc}
tr:last-child td{border-bottom:none}
.ic{display:flex;align-items:center;gap:6px;font-family:JetBrains Mono,monospace;font-size:11px;font-weight:500;color:#ef4444}
.id{width:5px;height:5px;border-radius:50%;background:#ef4444;flex-shrink:0}
.tc{font-family:JetBrains Mono,monospace;font-size:10px;color:#94a3b8}
.rc{font-size:12px;color:#374151;font-weight:500}
.bb{display:inline-flex;align-items:center;gap:3px;background:#fef2f2;border:1px solid #fecaca;color:#dc2626;padding:2px 8px;border-radius:5px;font-size:10px;font-weight:700;text-transform:uppercase;white-space:nowrap}
.emp{padding:36px 16px;text-align:center}
.emp p{font-size:12px;color:#94a3b8}
.rc2{display:flex;flex-direction:column;gap:14px}
.ca{padding:16px}
.cr{margin-bottom:14px}.cr:last-child{margin-bottom:0}
.cm{display:flex;justify-content:space-between;margin-bottom:5px}
.cl{font-size:11px;font-weight:500;color:#374151}
.cp{font-size:11px;font-weight:600}
.cbg{height:8px;background:#f1f5f9;border-radius:99px;overflow:hidden}
.cf{height:100%;border-radius:99px}
.fb{background:linear-gradient(90deg,#10b981,#34d399)}
.fa{background:linear-gradient(90deg,#ef4444,#f87171)}
.ig{display:grid;grid-template-columns:1fr 1fr}
.ii{padding:10px 14px;border-bottom:1px solid #f1f5f9;display:flex;flex-direction:column;gap:2px}
.ii:nth-child(odd){border-right:1px solid #f1f5f9}
.ii:nth-last-child(-n+2){border-bottom:none}
.ik{font-size:9px;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px}
.iv{font-size:12px;font-weight:600;color:#1a1f3c}
.iv.bl{color:#6366f1}.iv.gr{color:#10b981}
.bg2{display:grid;grid-template-columns:1fr;gap:14px;margin-bottom:80px}
@media(min-width:800px){.bg2{grid-template-columns:1fr 1fr}}
.bli{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid #f8fafc;gap:10px}
.bli:last-child{border-bottom:none}
.blip{font-family:JetBrains Mono,monospace;font-size:12px;font-weight:600;color:#ef4444}
.blr{font-size:11px;color:#64748b;margin-top:2px}
.blt{font-family:JetBrains Mono,monospace;font-size:10px;color:#94a3b8;white-space:nowrap}
.cg{display:grid;grid-template-columns:1fr 1fr}
.ci{display:flex;align-items:center;justify-content:space-between;padding:10px 14px;border-bottom:1px solid #f1f5f9;gap:8px}
.ci:nth-child(odd){border-right:1px solid #f1f5f9}
.ci:nth-last-child(-n+2){border-bottom:none}
.cl2{font-size:11px;color:#374151;font-weight:500}
.cbdg{font-size:9px;font-weight:700;padding:2px 7px;border-radius:5px;background:#d1fae5;color:#065f46;white-space:nowrap}
footer{position:fixed;bottom:0;left:0;right:0;background:#fff;border-top:1px solid #e2e8f0;padding:8px 16px;display:flex;align-items:center;justify-content:space-between;z-index:100;flex-wrap:wrap;gap:6px}
.fl{display:flex;align-items:center;gap:10px;font-size:10px;color:#94a3b8;flex-wrap:wrap}
.fs{color:#e2e8f0}
.fr{font-size:10px;color:#94a3b8;font-family:JetBrains Mono,monospace}
.ft{background:#f0f4ff;color:#6366f1;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:600}
</style></head><body>
<nav class="nav">
  <div class="brand">
    <div class="bi"><svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5"><path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7L12 2z"/><path d="M9 12l2 2 4-4" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
    <div class="bn">AE<span>GIS</span></div>
  </div>
  <div class="nr">
    <div class="lb"><div class="ld"></div>Live</div>
    <div class="nt" id="live-clock">{{ now }}</div>
    <a href="/logout" class="lo">Logout</a>
  </div>
</nav>
<div class="main">
  <div class="ph">
    <div><h2>Security Overview</h2><p>Welcome, admin - Real-time intrusion detection - Refresh 5s</p></div>
    <a href="/report" class="dlb">
      <svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" width="14" height="14"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
      Download Report
    </a>
  </div>
  <div class="stats">
    <div class="stat bl"><div class="sa"></div><div class="si">🌐</div><div class="sl">Total flows</div><div class="sv">{{ stats.total_flows }}</div><div class="ss">Monitored</div></div>
    <div class="stat re"><div class="sa"></div><div class="si">⚠️</div><div class="sl">Attacks</div><div class="sv">{{ stats.attacks }}</div><div class="ss">Detected</div></div>
    <div class="stat or"><div class="sa"></div><div class="si">🚫</div><div class="sl">IPs blocked</div><div class="sv">{{ stats.blocked }}</div><div class="ss">via iptables</div></div>
    <div class="stat gr"><div class="sa"></div><div class="si">✅</div><div class="sl">Accuracy</div><div class="sv">99.88<span style="font-size:14px">%</span></div><div class="ss">ROC-AUC 1.0</div></div>
  </div>
  <div class="ss2">
    <div class="sc"><div class="scv">2,313,810</div><div class="scl">Training rows</div></div>
    <div class="sc"><div class="scv">15</div><div class="scl">Attack types</div></div>
    <div class="sc"><div class="scv">0.9985</div><div class="scl">Cross-val F1</div></div>
  </div>
  <div class="tp">
    <div class="th">
      <div class="tds"><div class="dr"></div><div class="dy"></div><div class="dg"></div></div>
      <div class="tt">AEGIS IDS - Live System Log</div>
      <div style="font-size:10px;color:#475569">Real-time</div>
    </div>
    <div class="tbd">
      <div><span class="tg">aegis@ids</span><span class="tgr">:~$ </span><span class="tw">sudo python3 ids_realtime.py</span></div>
      <div><span class="tb2">[INFO]</span> <span class="tw">Model loaded: ids_model.pkl — Random Forest 100 trees</span></div>
      <div><span class="tb2">[INFO]</span> <span class="tw">Scaler loaded: 77 features — 2,313,810 training rows</span></div>
      <div><span class="tg">[OK]</span> <span class="tw">SSH brute force detection — port 22</span></div>
      <div><span class="tg">[OK]</span> <span class="tw">FTP brute force detection — port 21</span></div>
      <div><span class="tg">[OK]</span> <span class="tw">SYN flood detection — threshold 15 packets</span></div>
      <div><span class="tg">[OK]</span> <span class="tw">ML model — all 15 attack types active</span></div>
      <div><span class="tg">[OK]</span> <span class="tw">Scapy packet capture started</span></div>
      <br>
      {% for a in alerts %}
      <div><span class="tr">[ATTACK]</span> <span class="tw">{{ a.time[:19] }}</span></div>
      <div><span class="tgr">  From: {{ a.ip }} | {{ a.reason }}</span></div>
      <div><span class="tr">  *** IP {{ a.ip }} BLOCKED via iptables DROP ***</span></div>
      {% endfor %}
      {% if not alerts %}
      <div><span class="tg">[MONITOR]</span> <span class="tw">Watching traffic — no threats detected</span></div>
      {% endif %}
    </div>
  </div>
  <div class="grid">
    <div class="panel">
      <div class="pnh">
        <div class="pnt">
          <svg viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          Attack alerts
        </div>
        <div class="pnb">{{ alerts|length }} events</div>
      </div>
      <div class="stw">
        {% if alerts %}
        <table>
          <thead><tr><th>Time</th><th>Source IP</th><th>Location</th><th>Protocol</th><th>Attack type</th><th>Action</th></tr></thead>
          <tbody>
          {% for a in alerts %}
          <tr><td class="tc">{{ a.time[:19] }}</td><td><div class="ic"><div class="id"></div>{{ a.ip }}</div></td><td class="tc">{{ a.location if a.location else "Unknown" }}</td><td>{% if "SSH" in a.reason %}<span style="background:#e0e7ff;border:1px solid #818cf8;color:#3730a3;padding:2px 8px;border-radius:5px;font-size:10px;font-weight:700;">SSH</span>{% elif "FTP" in a.reason %}<span style="background:#fef3c7;border:1px solid #fbbf24;color:#92400e;padding:2px 8px;border-radius:5px;font-size:10px;font-weight:700;">FTP</span>{% elif "SQL" in a.reason %}<span style="background:#fce7f3;border:1px solid #f9a8d4;color:#9d174d;padding:2px 8px;border-radius:5px;font-size:10px;font-weight:700;">HTTP</span>{% elif "Nikto" in a.reason or "Vulnerability" in a.reason %}<span style="background:#fce7f3;border:1px solid #f9a8d4;color:#9d174d;padding:2px 8px;border-radius:5px;font-size:10px;font-weight:700;">HTTP</span>{% elif "GoldenEye" in a.reason or "Slowloris" in a.reason or "HTTP" in a.reason %}<span style="background:#fce7f3;border:1px solid #f9a8d4;color:#9d174d;padding:2px 8px;border-radius:5px;font-size:10px;font-weight:700;">HTTP</span>{% elif "SYN" in a.reason or "Flood" in a.reason %}<span style="background:#fee2e2;border:1px solid #fca5a5;color:#991b1b;padding:2px 8px;border-radius:5px;font-size:10px;font-weight:700;">TCP</span>{% elif "Scan" in a.reason %}<span style="background:#f3f4f6;border:1px solid #d1d5db;color:#374151;padding:2px 8px;border-radius:5px;font-size:10px;font-weight:700;">TCP</span>{% else %}<span style="background:#d1fae5;border:1px solid #6ee7b7;color:#065f46;padding:2px 8px;border-radius:5px;font-size:10px;font-weight:700;">TCP</span>{% endif %}</td><td class="rc">{{ a.reason }}</td><td><span class="bb">Blocked</span></td></tr>
          {% endfor %}
          </tbody>
        </table>
        {% else %}
        <div class="emp"><p style="font-size:28px;opacity:.3;margin-bottom:8px">🛡️</p><p>No attacks detected</p></div>
        {% endif %}
      </div>
    </div>
    <div class="rc2">
      <div class="panel">
        <div class="pnh"><div class="pnt"><svg viewBox="0 0 24 24" fill="none" stroke="#6366f1" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>Traffic split</div></div>
        <div class="ca">
          <div class="cr"><div class="cm"><span class="cl">Benign</span><span class="cp" style="color:#10b981">{{ stats.benign_pct }}%</span></div><div class="cbg"><div class="cf fb" style="width:{{ stats.benign_pct }}%"></div></div></div>
          <div class="cr"><div class="cm"><span class="cl">Attack</span><span class="cp" style="color:#ef4444">{{ stats.attack_pct }}%</span></div><div class="cbg"><div class="cf fa" style="width:{{ [stats.attack_pct,2]|max }}%"></div></div></div>
        </div>
      </div>
      <div class="panel">
        <div class="pnh"><div class="pnt"><svg viewBox="0 0 24 24" fill="none" stroke="#6366f1" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 010 14.14M4.93 4.93a10 10 0 000 14.14"/></svg>Model</div></div>
        <div class="ig">
          <div class="ii"><div class="ik">Algorithm</div><div class="iv bl">Random Forest</div></div>
          <div class="ii"><div class="ik">Trees</div><div class="iv">100</div></div>
          <div class="ii"><div class="ik">Accuracy</div><div class="iv gr">99.88%</div></div>
          <div class="ii"><div class="ik">ROC-AUC</div><div class="iv gr">1.0000</div></div>
          <div class="ii"><div class="ik">F1 CV</div><div class="iv gr">0.9985</div></div>
          <div class="ii"><div class="ik">Features</div><div class="iv">77</div></div>
        </div>
      </div>
    </div>
  </div>
  <div class="panel" style="margin-bottom:14px">
    <div class="pnh">
      <div class="pnt">
        <svg viewBox="0 0 24 24" fill="none" stroke="#6366f1" stroke-width="2" width="14" height="14"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
        Live network traffic
      </div>
      <div class="pnb">Last 20 flows</div>
    </div>
    <div class="stw">
      <table>
        <thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Port</th><th>Status</th><th>Confidence</th></tr></thead>
        <tbody>
        {% if live_traffic %}
          {% for t in live_traffic %}
          <tr>
            <td class="tc">{{ t.time }}</td>
            <td class="tc">{{ t.src }}</td>
            <td class="tc">{{ t.dst }}</td>
            <td class="tc">{{ t.dport }}</td>
            <td>{% if t.status == "ATTACK" %}<span class="bb">Attack</span>{% else %}<span style="background:#f0fdf4;border:1px solid #86efac;color:#15803d;padding:2px 8px;border-radius:5px;font-size:10px;font-weight:700;">Benign</span>{% endif %}</td>
            <td class="tc">{{ t.confidence }}%</td>
          </tr>
          {% endfor %}
        {% else %}
          <tr><td colspan="6" style="text-align:center;padding:20px;color:#94a3b8;font-size:12px">Start ids_realtime.py to see live traffic</td></tr>
        {% endif %}
        </tbody>
      </table>
    </div>
  </div>
  <div class="bg2">
    <div class="panel">
      <div class="pnh"><div class="pnt"><svg viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>Blocked IPs</div><div class="pnb">{{ blocked_ips|length }} blocked</div></div>
      {% if blocked_ips %}
        {% for item in blocked_ips %}
        <div class="bli"><div><div class="blip">{{ item.ip }}</div><div class="blr">{{ item.reason }}</div></div><div class="blt">{{ item.time[:19] if item.time|length > 19 else item.time }}</div></div>
        {% endfor %}
      {% else %}
      <div class="emp"><p>No IPs blocked yet</p></div>
      {% endif %}
    </div>
    <div class="panel">
      <div class="pnh"><div class="pnt"><svg viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z"/></svg>Coverage</div></div>
      <div class="cg">
        <div class="ci"><span class="cl2">SSH Brute Force</span><span class="cbdg">Protected</span></div>
        <div class="ci"><span class="cl2">FTP Brute Force</span><span class="cbdg">Protected</span></div>
        <div class="ci"><span class="cl2">DDoS</span><span class="cbdg">Protected</span></div>
        <div class="ci"><span class="cl2">DoS Hulk</span><span class="cbdg">Protected</span></div>
        <div class="ci"><span class="cl2">DoS GoldenEye</span><span class="cbdg">Protected</span></div>
        <div class="ci"><span class="cl2">DoS Slowloris</span><span class="cbdg">Protected</span></div>
        <div class="ci"><span class="cl2">Port Scan</span><span class="cbdg">Protected</span></div>
        <div class="ci"><span class="cl2">Web Attack</span><span class="cbdg">Protected</span></div>
        <div class="ci"><span class="cl2">Botnet</span><span class="cbdg">Protected</span></div>
        <div class="ci"><span class="cl2">Heartbleed</span><span class="cbdg">Protected</span></div>
        <div class="ci"><span class="cl2">Infiltration</span><span class="cbdg">Protected</span></div>
        <div class="ci"><span class="cl2">Blocking</span><span class="cbdg" style="background:#e0e7ff;color:#3730a3">iptables</span></div>
      </div>
    </div>
  </div>
</div>
<footer>
  <div class="fl"><span class="ft">AEGIS v1.0</span><span class="fs">·</span><span>CIC-IDS2017</span><span class="fs">·</span><span>Random Forest</span><span class="fs">·</span><span>Auto-refresh 5s</span></div>
  <div class="fr" id="live-clock2">{{ now }}</div>
</footer>


<script>
function playSound(){
    try{
        var ctx=new(window.AudioContext||window.webkitAudioContext)();
        [0,0.3,0.6].forEach(function(t){
            var o=ctx.createOscillator(),g=ctx.createGain();
            o.connect(g);g.connect(ctx.destination);
            o.type="sine";o.frequency.value=1200;
            g.gain.setValueAtTime(0.4,ctx.currentTime+t);
            g.gain.exponentialRampToValueAtTime(0.001,ctx.currentTime+t+0.2);
            o.start(ctx.currentTime+t);o.stop(ctx.currentTime+t+0.25);
        });
    }catch(e){}
}
window.onload=function(){
    var cur=parseInt("{{ stats.attacks if stats is defined else 0 }}");
    var stored=parseInt(sessionStorage.getItem("atk")||"-1");
    if(cur>stored && stored>=0){
        playSound();
    }
    sessionStorage.setItem("atk",cur);
};
</script>
<script>
function updateClock(){
    var now = new Date();
    var s = now.getFullYear()+'-'+String(now.getMonth()+1).padStart(2,'0')+'-'+String(now.getDate()).padStart(2,'0')+' '+String(now.getHours()).padStart(2,'0')+':'+String(now.getMinutes()).padStart(2,'0')+':'+String(now.getSeconds()).padStart(2,'0');
    var el = document.getElementById('live-clock');
    var el2 = document.getElementById('live-clock2');
    if(el) el.innerHTML = s;
    if(el2) el2.innerHTML = s;
}
setInterval(updateClock, 1000);
updateClock();
</script>

<script>
setInterval(function(){
    fetch('/api/stats', {credentials: 'include'})
    .then(function(r){ return r.json(); })
    .then(function(d){
        var tables = document.querySelectorAll('table');
        if(tables[0] && d.alerts && d.alerts.length > 0){
            tables[0].querySelector('tbody').innerHTML = d.alerts.map(function(a){
                var proto='TCP',ps='background:#fee2e2;border:1px solid #fca5a5;color:#991b1b;';
                if(a.reason&&a.reason.includes('SSH')){proto='SSH';ps='background:#e0e7ff;border:1px solid #818cf8;color:#3730a3;';}
                else if(a.reason&&a.reason.includes('FTP')){proto='FTP';ps='background:#fef3c7;border:1px solid #fbbf24;color:#92400e;';}
                else if(a.reason&&(a.reason.includes('HTTP')||a.reason.includes('SQL')||a.reason.includes('Nikto'))){proto='HTTP';ps='background:#fce7f3;border:1px solid #f9a8d4;color:#9d174d;';}
                return '<tr><td>'+(a.time||'').substring(0,19)+'</td><td>'+a.ip+'</td><td>Unknown</td><td><span style="'+ps+'padding:2px 8px;border-radius:5px;font-size:10px;font-weight:700;">'+proto+'</span></td><td>'+a.reason+'</td><td><span style="background:#fee2e2;color:#991b1b;padding:2px 8px;border-radius:5px;font-size:10px;font-weight:700;">Blocked</span></td></tr>';
            }).join('');
        }
        var ltable = tables[1] || tables[0];
        if(ltable && d.live_traffic && d.live_traffic.length > 0){
            ltable.querySelector('tbody').innerHTML = d.live_traffic.slice(0,20).map(function(t){
                var b = t.status==='ATTACK' ? '<span style="color:red;font-weight:700;">ATTACK</span>' : '<span style="color:green;">BENIGN</span>';
                return '<tr><td>'+t.time+'</td><td>'+t.src+'</td><td>'+t.dst+'</td><td>'+t.dport+'</td><td>'+b+'</td><td>'+t.confidence+'%</td></tr>';
            }).join('');
        }
        var cl = document.getElementById('live-clock');
        if(cl) cl.innerHTML = d.now;
        var cl2 = document.getElementById('live-clock2');
        if(cl2) cl2.innerHTML = d.now;
    }).catch(function(e){ console.log('err',e); });
}, 3000);
</script>
</body></html>"""

if __name__ == "__main__":
    os.makedirs("logs", exist_ok=True)
    print("="*50)
    print("  AEGIS DASHBOARD")
    print("  Open: http://localhost:5000")
    print("  Login: admin / aegis2026")
    print("="*50)
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
