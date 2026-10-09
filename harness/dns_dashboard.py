#!/usr/bin/env python3
"""
NetDecoy — Interactive DNS Control Dashboard & Server

Provides a local web dashboard (http://localhost:8080) to seamlessly toggle
between GOOD DNS (Benign Forwarder) and BAD DNS (Spoofing Attacker) modes
in real time.

Usage (PowerShell as Administrator):
    python dns_dashboard.py
    (then open http://localhost:8080 in your browser)
"""
import argparse
import json
import os
import socket
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dnslib import DNSRecord, DNSHeader, QTYPE, RR, A, RCODE
from dnslib.server import DNSServer, BaseResolver

UPSTREAM = "1.1.1.1"
UPSTREAM_PORT = 53


def get_local_ips():
    ips = []
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if not ip.startswith("127."):
                ips.append(ip)
    except Exception:
        pass
    return ips or ["127.0.0.1"]


class ServerState:
    def __init__(self):
        self.lock = threading.Lock()
        self.mode = "good"  # "good" (clean) or "bad" (spoof)
        local_ips = get_local_ips()
        self.sinkhole_ip = local_ips[0] if local_ips else "127.0.0.1"
        self.targets = ["google.com", "example.com", "bank.com", "one.one.one.one"]
        self.logs = []
        self.dns_running = False
        self.dns_error = None
        self.dns_port = 53

    def matches_target(self, qname):
        q = qname.rstrip(".").lower()
        with self.lock:
            return any(q == t or q.endswith("." + t) for t in self.targets)

    def add_log(self, qname, qtype, client_ip, action, answer):
        with self.lock:
            entry = {
                "id": int(time.time() * 1000) + len(self.logs),
                "time": datetime.now().strftime("%H:%M:%S"),
                "qname": qname,
                "qtype": qtype,
                "client": client_ip,
                "action": action,
                "answer": answer,
            }
            self.logs.insert(0, entry)
            if len(self.logs) > 100:
                self.logs.pop()

    def get_status(self):
        with self.lock:
            return {
                "mode": self.mode,
                "sinkhole_ip": self.sinkhole_ip,
                "targets": list(self.targets),
                "dns_running": self.dns_running,
                "dns_error": self.dns_error,
                "dns_port": self.dns_port,
                "local_ips": get_local_ips(),
                "logs": list(self.logs[:40]),
            }


state = ServerState()


class DashboardResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".").lower()
        qtype = QTYPE.get(request.q.qtype, "UNKNOWN")
        client_ip = handler.client_address[0] if handler and hasattr(handler, "client_address") else "client"

        # Check if malicious spoof mode is active for this domain
        is_bad = False
        with state.lock:
            is_bad = (state.mode == "bad")
            sinkhole = state.sinkhole_ip

        if is_bad and qtype == "A" and state.matches_target(qname):
            reply = DNSRecord(
                DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
                q=request.q,
            )
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(sinkhole), ttl=60))
            state.add_log(qname, qtype, client_ip, "SPOOFED", sinkhole)
            print(f" [!] SPOOFED: {qname} -> {sinkhole} (for {client_ip})", flush=True)
            return reply

        # Clean truthful forwarder
        try:
            raw = request.send(UPSTREAM, UPSTREAM_PORT, timeout=3)
            reply = DNSRecord.parse(raw)
            answers = [str(r.rdata) for r in reply.rr if r.rtype == 1]
            ans_str = ", ".join(answers[:3]) or "OK"
            state.add_log(qname, qtype, client_ip, "CLEAN", ans_str)
            print(f" [*] CLEAN:   {qname} -> {ans_str}", flush=True)
            return reply
        except Exception as e:
            state.add_log(qname, qtype, client_ip, "ERROR", str(e))
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            return reply


HTML_DASHBOARD = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NetDecoy — DNS Controller Dashboard</title>
  <style>
    :root {
      --bg: #070d18;
      --card: #0f172a;
      --border: #1e293b;
      --text: #f8fafc;
      --muted: #94a3b8;
      --accent-good: #10b981;
      --accent-bad: #ef4444;
      --blue: #38bdf8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
    body { background: var(--bg); color: var(--text); padding: 24px; min-height: 100vh; }
    .container { max-width: 900px; margin: 0 auto; }
    header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid var(--border); }
    h1 { font-size: 24px; font-weight: 800; }
    .status-badge { padding: 6px 12px; border-radius: 999px; font-size: 12px; font-weight: 800; text-transform: uppercase; letter-spacing: 1px; }
    .mode-good { background: #064e3b; color: #34d399; border: 1px solid #059669; }
    .mode-bad { background: #7f1d1d; color: #f87171; border: 1px solid #dc2626; }
    .toggle-card { background: var(--card); border: 2px solid var(--border); border-radius: 16px; padding: 28px; text-align: center; margin-bottom: 24px; transition: border-color 0.2s; }
    .toggle-card.good { border-color: var(--accent-good); box-shadow: 0 0 25px rgba(16, 185, 129, 0.15); }
    .toggle-card.bad { border-color: var(--accent-bad); box-shadow: 0 0 25px rgba(239, 68, 68, 0.2); }
    .toggle-title { font-size: 18px; color: var(--muted); margin-bottom: 12px; }
    .toggle-btns { display: flex; gap: 16px; justify-content: center; max-width: 500px; margin: 0 auto 16px; }
    .btn { flex: 1; padding: 16px 20px; font-size: 16px; font-weight: 800; border-radius: 12px; border: 0; cursor: pointer; transition: all 0.15s; }
    .btn-good { background: #065f46; color: #a7f3d0; }
    .btn-good.active { background: var(--accent-good); color: #022c22; box-shadow: 0 4px 15px rgba(16, 185, 129, 0.4); transform: scale(1.02); }
    .btn-bad { background: #7f1d1d; color: #fecaca; }
    .btn-bad.active { background: var(--accent-bad); color: #450a0a; box-shadow: 0 4px 15px rgba(239, 68, 68, 0.4); transform: scale(1.02); }
    .mode-desc { font-size: 14px; color: var(--muted); }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; margin-bottom: 24px; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 18px; }
    .card-title { font-size: 14px; font-weight: 700; color: var(--blue); margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
    .info-row { display: flex; justify-content: space-between; padding: 6px 0; font-size: 13px; border-bottom: 1px solid #142036; }
    .info-row:last-child { border: 0; }
    .info-label { color: var(--muted); }
    .info-val { font-family: monospace; font-weight: 600; color: #e2e8f0; }
    .tag-container { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
    .tag { background: #1e293b; color: #cbd5e1; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-family: monospace; display: flex; align-items: center; gap: 6px; }
    .tag-remove { cursor: pointer; color: #ef4444; font-weight: bold; }
    .input-row { display: flex; gap: 8px; margin-top: 10px; }
    input[type="text"] { flex: 1; background: #070d18; border: 1px solid var(--border); color: #fff; padding: 8px 12px; border-radius: 8px; font-size: 13px; font-family: monospace; }
    .btn-small { background: #1e293b; color: #fff; border: 1px solid #334155; padding: 8px 14px; border-radius: 8px; font-size: 12px; font-weight: 700; cursor: pointer; }
    .log-table { width: 100%; border-collapse: collapse; font-size: 12px; font-family: monospace; margin-top: 8px; }
    .log-table th { text-align: left; padding: 8px 6px; color: var(--muted); border-bottom: 1px solid var(--border); }
    .log-table td { padding: 8px 6px; border-bottom: 1px solid #142036; }
    .badge-spoof { color: #f87171; font-weight: 800; background: rgba(239, 68, 68, 0.15); padding: 2px 6px; border-radius: 4px; }
    .badge-clean { color: #34d399; font-weight: 700; background: rgba(16, 185, 129, 0.15); padding: 2px 6px; border-radius: 4px; }
    .help-banner { background: #0c1c38; border: 1px solid #1e3a6e; border-radius: 12px; padding: 14px; font-size: 13px; color: #bfdbfe; margin-bottom: 24px; line-height: 1.5; }
    .help-banner strong { color: #fff; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>NetDecoy DNS Controller</h1>
        <p style="color:var(--muted); font-size:13px; margin-top:4px;">Toggle and live-monitor DNS resolution behavior for NetDecoy testing</p>
      </div>
      <div id="modeBadge" class="status-badge mode-good">SAFE MODE ACTIVE</div>
    </header>

    <div class="help-banner">
      <strong>📱 Mobile Hotspot / Wi-Fi Setup:</strong>
      Turn on Windows Mobile Hotspot or connect phone & laptop to the same Wi-Fi. On the phone, set <strong>DNS 1</strong> to your laptop IP: <code id="suggestedIp" style="background:#070d18; padding:2px 6px; border-radius:4px; color:#38bdf8;">Loading...</code> (keep Private DNS turned <strong>Off</strong>).
    </div>

    <div id="toggleCard" class="toggle-card good">
      <div class="toggle-title">Live DNS Resolution Mode</div>
      <div class="toggle-btns">
        <button id="btnGood" class="btn btn-good active" onclick="setMode('good')">
          🟢 GOOD DNS<br><span style="font-size:11px; font-weight:normal;">Truthful (NetDecoy SAFE)</span>
        </button>
        <button id="btnBad" class="btn btn-bad" onclick="setMode('bad')">
          🔴 BAD DNS<br><span style="font-size:11px; font-weight:normal;">Spoof Attacker (NetDecoy ALERT)</span>
        </button>
      </div>
      <p id="modeDesc" class="mode-desc">
        Incoming queries are forwarded truthfully to Cloudflare 1.1.1.1. NetDecoy will verify all canaries as SAFE.
      </p>
    </div>

    <div class="grid">
      <div class="card">
        <div class="card-title">Attacker Configuration</div>
        <div class="info-row">
          <span class="info-label">DNS Listener Port</span>
          <span id="dnsPort" class="info-val">53 (UDP)</span>
        </div>
        <div class="info-row">
          <span class="info-label">Sinkhole IP (Spoofed Address)</span>
          <span id="sinkholeVal" class="info-val">-</span>
        </div>
        <div class="input-row">
          <input type="text" id="sinkholeInput" placeholder="New sinkhole IP (e.g. 192.168.137.1)">
          <button class="btn-small" onclick="updateSinkhole()">Update IP</button>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Target Domains to Spoof</div>
        <div style="font-size:12px; color:var(--muted); margin-bottom:6px;">These domains are hijacked when BAD DNS mode is active:</div>
        <div id="targetsWrap" class="tag-container"></div>
        <div class="input-row">
          <input type="text" id="targetInput" placeholder="Add domain (e.g. bank.com)">
          <button class="btn-small" onclick="addTarget()">+ Add</button>
        </div>
      </div>
    </div>

    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
        <div class="card-title" style="margin:0;">Live DNS Traffic Log (Auto-refreshing)</div>
        <button class="btn-small" onclick="clearLogs()">Clear Log</button>
      </div>
      <table class="log-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Client</th>
            <th>Domain</th>
            <th>Type</th>
            <th>Action</th>
            <th>Resolved Result</th>
          </tr>
        </thead>
        <tbody id="logsBody">
          <tr><td colspan="6" style="text-align:center; color:var(--muted);">Waiting for queries...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <script>
    let currentMode = 'good';

    async function fetchStatus() {
      try {
        const res = await fetch('/api/status');
        const data = await res.json();
        render(data);
      } catch (e) {
        console.error(e);
      }
    }

    function render(data) {
      currentMode = data.mode;
      const isGood = data.mode === 'good';

      // Badge
      const badge = document.getElementById('modeBadge');
      badge.className = 'status-badge ' + (isGood ? 'mode-good' : 'mode-bad');
      badge.textContent = isGood ? 'SAFE MODE ACTIVE' : 'SPOOF ATTACK ACTIVE';

      // Card
      const card = document.getElementById('toggleCard');
      card.className = 'toggle-card ' + (isGood ? 'good' : 'bad');

      // Buttons
      document.getElementById('btnGood').className = 'btn btn-good ' + (isGood ? 'active' : '');
      document.getElementById('btnBad').className = 'btn btn-bad ' + (!isGood ? 'active' : '');

      // Description
      document.getElementById('modeDesc').textContent = isGood
        ? 'Incoming queries are forwarded truthfully to Cloudflare 1.1.1.1. NetDecoy will verify all canaries as SAFE.'
        : `Target domains are intercepted and answered with sinkhole IP ${data.sinkhole_ip}. NetDecoy will flag ALERT!`;

      // Info
      document.getElementById('sinkholeVal').textContent = data.sinkhole_ip;
      document.getElementById('dnsPort').textContent = `${data.dns_port} (UDP) ${data.dns_running ? '🟢 RUNNING' : '🔴 ERROR: ' + (data.dns_error || 'Stopped')}`;
      if (data.local_ips.length > 0) {
        document.getElementById('suggestedIp').textContent = data.local_ips.join(' or ');
      }

      // Targets
      const tagWrap = document.getElementById('targetsWrap');
      tagWrap.innerHTML = data.targets.map(t =>
        `<span class="tag">${t} <span class="tag-remove" onclick="removeTarget('${t}')">✕</span></span>`
      ).join('');

      // Logs
      const tbody = document.getElementById('logsBody');
      if (data.logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--muted); padding:16px;">No DNS queries yet. Tap "Scan Network" in the app!</td></tr>';
      } else {
        tbody.innerHTML = data.logs.map(l => `
          <tr>
            <td>${l.time}</td>
            <td>${l.client}</td>
            <td style="color:#f8fafc; font-weight:bold;">${l.qname}</td>
            <td>${l.qtype}</td>
            <td><span class="${l.action === 'SPOOFED' ? 'badge-spoof' : 'badge-clean'}">${l.action}</span></td>
            <td>${l.answer}</td>
          </tr>
        `).join('');
      }
    }

    async function setMode(mode) {
      await fetch('/api/mode', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ mode }) });
      fetchStatus();
    }

    async function updateSinkhole() {
      const input = document.getElementById('sinkholeInput');
      const val = input.value.trim();
      if (val) {
        await fetch('/api/sinkhole', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ sinkhole: val }) });
        input.value = '';
        fetchStatus();
      }
    }

    async function addTarget() {
      const input = document.getElementById('targetInput');
      const val = input.value.trim().toLowerCase();
      if (val) {
        await fetch('/api/targets', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ action: 'add', target: val }) });
        input.value = '';
        fetchStatus();
      }
    }

    async function removeTarget(t) {
      await fetch('/api/targets', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ action: 'remove', target: t }) });
      fetchStatus();
    }

    async function clearLogs() {
      await fetch('/api/clear_logs', { method: 'POST' });
      fetchStatus();
    }

    fetchStatus();
    setInterval(fetchStatus, 1000);
  </script>
</body>
</html>
"""


class DashboardHTTPHandler(BaseHTTPRequestHandler):
    def _send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            body = HTML_DASHBOARD.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/status":
            self._send_json(state.get_status())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        try:
            body = json.loads(raw)
        except Exception:
            body = {}

        if self.path == "/api/mode":
            mode = body.get("mode")
            if mode in ["good", "bad"]:
                with state.lock:
                    state.mode = mode
                print(f"\n[DASHBOARD] Switched DNS Mode to: >>> {mode.upper()} <<<", flush=True)
            self._send_json({"success": True, "mode": state.mode})

        elif self.path == "/api/sinkhole":
            ip = body.get("sinkhole", "").strip()
            if ip:
                with state.lock:
                    state.sinkhole_ip = ip
                print(f"[DASHBOARD] Sinkhole IP updated to: {ip}", flush=True)
            self._send_json({"success": True, "sinkhole_ip": state.sinkhole_ip})

        elif self.path == "/api/targets":
            action = body.get("action")
            target = body.get("target", "").strip().lower()
            with state.lock:
                if action == "add" and target and target not in state.targets:
                    state.targets.append(target)
                elif action == "remove" and target in state.targets:
                    state.targets.remove(target)
            self._send_json({"success": True, "targets": state.targets})

        elif self.path == "/api/clear_logs":
            with state.lock:
                state.logs.clear()
            self._send_json({"success": True})

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):
        pass  # suppress HTTP noisy console logs


def start_dns_server(port, address):
    state.dns_port = port
    resolver = DashboardResolver()
    server = DNSServer(resolver, port=port, address=address)
    try:
        state.dns_running = True
        state.dns_error = None
        server.start()
    except Exception as e:
        state.dns_running = False
        state.dns_error = str(e)
        print(f"\n[!] WARNING: Could not bind DNS on port {port}: {e}")
        print("    If port 53 is busy, run PowerShell as Administrator or stop conflicting services.\n", flush=True)


def main():
    ap = argparse.ArgumentParser(description="NetDecoy Live DNS Controller Dashboard")
    ap.add_argument("--web-port", type=int, default=8080, help="Web UI dashboard port (default: 8080)")
    ap.add_argument("--dns-port", type=int, default=53, help="DNS listener port (default: 53)")
    ap.add_argument("--address", default="0.0.0.0", help="Address to bind (default: 0.0.0.0)")
    args = ap.parse_args()

    # Start DNS server in background thread
    dns_thread = threading.Thread(
        target=start_dns_server,
        args=(args.dns_port, args.address),
        daemon=True,
    )
    dns_thread.start()

    time.sleep(0.5)

    local_ips = get_local_ips()
    web_server = ThreadingHTTPServer((args.address, args.web_port), DashboardHTTPHandler)

    print("=" * 70)
    print("  🛡 NETDECOY INTERACTIVE DNS CONTROLLER & TEST HARNESS")
    print("=" * 70)
    print(f" Web Dashboard : http://localhost:{args.web_port}")
    if local_ips:
        print(f" LAN Dashboard : http://{local_ips[0]}:{args.web_port}")
    print(f" DNS Server    : {args.address}:{args.dns_port} (UDP)")
    print(f" Initial Mode  : 🟢 GOOD DNS (Benign Forwarder)")
    print("=" * 70)
    print("\nOpen http://localhost:8080 in your browser to toggle Good/Bad DNS.\n")

    try:
        web_server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping NetDecoy Dashboard.")
        web_server.shutdown()
        sys.exit(0)


if __name__ == "__main__":
    main()
