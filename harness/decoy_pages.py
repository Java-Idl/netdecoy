"""
NetDecoy — Sarcastic Decoy Web Pages for Spoofed Domains
Generates humorous, educational warning pages when a user visits a hijacked domain
(e.g. amrita.com, google.com, bank.com).
"""
import html


def render_decoy_page(host: str, path: str = "/") -> str:
    host_clean = host.split(":")[0].lower()

    if "amrita" in host_clean:
        return _render_amrita(host_clean)
    elif "google" in host_clean:
        return _render_google(host_clean)
    elif "bank" in host_clean:
        return _render_bank(host_clean)
    else:
        return _render_generic(host_clean)


def _render_amrita(host: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Amrita Vishwa Vidyapeetham - Decoy Portal</title>
  <style>
    body {{
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #0b1220;
      color: #e2e8f0;
      margin: 0;
      padding: 20px;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
    }}
    .card {{
      background: #111e38;
      border: 2px solid #a855f7;
      border-radius: 20px;
      padding: 36px 28px;
      max-width: 500px;
      width: 100%;
      box-shadow: 0 20px 60px rgba(168, 85, 247, 0.25);
      text-align: center;
    }}
    .badge {{
      display: inline-block;
      background: #7e22ce;
      color: #f3e8ff;
      font-weight: 800;
      font-size: 11px;
      letter-spacing: 1.5px;
      padding: 6px 14px;
      border-radius: 999px;
      margin-bottom: 16px;
      text-transform: uppercase;
    }}
    h1 {{
      font-size: 24px;
      color: #f8fafc;
      margin-bottom: 8px;
    }}
    .sarcasm {{
      font-size: 16px;
      color: #c084fc;
      font-weight: 700;
      margin-bottom: 20px;
    }}
    p {{
      font-size: 14px;
      color: #94a3b8;
      line-height: 1.6;
      margin-bottom: 16px;
    }}
    .stats-box {{
      background: #070d18;
      border: 1px solid #1e293b;
      border-radius: 12px;
      padding: 16px;
      margin: 20px 0;
      text-align: left;
      font-family: monospace;
      font-size: 13px;
    }}
    .stats-row {{
      display: flex;
      justify-content: space-between;
      margin-bottom: 8px;
    }}
    .stats-row:last-child {{ margin-bottom: 0; }}
    .fake-form {{
      margin-top: 20px;
      text-align: left;
    }}
    label {{
      font-size: 12px;
      font-weight: 600;
      color: #cbd5e1;
      display: block;
      margin-bottom: 4px;
    }}
    input {{
      width: 100%;
      box-sizing: border-box;
      padding: 10px 14px;
      background: #070d18;
      border: 1px solid #334155;
      border-radius: 8px;
      color: #fff;
      font-size: 14px;
      margin-bottom: 12px;
    }}
    button {{
      width: 100%;
      background: #a855f7;
      color: #fff;
      font-weight: 800;
      padding: 12px;
      border: 0;
      border-radius: 10px;
      cursor: pointer;
      font-size: 15px;
    }}
    .footer-note {{
      font-size: 11px;
      color: #f59e0b;
      margin-top: 18px;
      font-weight: 600;
    }}
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">🎓 AMRITA VISHWA VIDYAPEETHAM 🎓</div>
    <h1>Congratulations! 🎉</h1>
    <div class="sarcasm">You have been successfully bamboozled.</div>
    <p>
      You thought you were opening <strong>{html.escape(host)}</strong> to check AUMS or campus attendance,
      but your DNS queries were redirected to this sinkhole!
    </p>

    <div class="stats-box">
      <div class="stats-row"><span style="color:#94a3b8;">Requested:</span><span style="color:#38bdf8;">{html.escape(host)}</span></div>
      <div class="stats-row"><span style="color:#94a3b8;">DNS Attack:</span><span style="color:#ef4444;">Active Spoofing</span></div>
      <div class="stats-row"><span style="color:#94a3b8;">Your Attendance:</span><span style="color:#10b981;">100% (Lab Demo)</span></div>
      <div class="stats-row"><span style="color:#94a3b8;">NetDecoy Status:</span><span style="color:#ef4444;">ALERT (Flagged)</span></div>
    </div>

    <form class="fake-form" onsubmit="event.preventDefault(); alert('🚨 BEEP BOOP! You just handed your login credentials to a spoofed rogue server! Luckily, this is NetDecoy saving your credentials.');">
      <label>Roll Number</label>
      <input type="text" placeholder="e.g. CB.EN.U4CSE21XXX" required>
      <label>Amrita Wi-Fi / AUMS Password</label>
      <input type="password" placeholder="••••••••••••" required>
      <button type="submit">Submit Fake Credentials</button>
    </form>

    <div class="footer-note">
      🛡 NetDecoy Demonstration Decoy — No actual credentials are stored.
    </div>
  </div>
</body>
</html>
"""


def _render_google(host: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Goögle — Definitely Real Google</title>
  <style>
    body {{
      font-family: system-ui, sans-serif;
      background: #202124;
      color: #e8eaed;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      padding: 20px;
    }}
    .logo {{
      font-size: 52px;
      font-weight: 800;
      letter-spacing: -2px;
      margin-bottom: 20px;
    }}
    .logo span:nth-child(1) {{ color: #4285f4; }}
    .logo span:nth-child(2) {{ color: #ea4335; }}
    .logo span:nth-child(3) {{ color: #fbbc05; }}
    .logo span:nth-child(4) {{ color: #4285f4; }}
    .logo span:nth-child(5) {{ color: #34a853; }}
    .logo span:nth-child(6) {{ color: #ea4335; }}
    .search-box {{
      background: #303134;
      border: 1px solid #5f6368;
      border-radius: 24px;
      padding: 12px 20px;
      width: 100%;
      max-width: 500px;
      color: #fff;
      font-size: 16px;
      outline: none;
      margin-bottom: 20px;
      box-sizing: border-box;
    }}
    .btns {{ display: flex; gap: 12px; }}
    button {{
      background: #303134;
      border: 1px solid #5f6368;
      color: #e8eaed;
      padding: 10px 18px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 14px;
    }}
    .sarcasm-card {{
      background: #281414;
      border: 1px solid #7f1d1d;
      border-radius: 12px;
      padding: 18px;
      margin-top: 30px;
      max-width: 480px;
      text-align: center;
    }}
  </style>
</head>
<body>
  <div class="logo">
    <span>G</span><span>o</span><span>ö</span><span>g</span><span>l</span><span>e</span>
  </div>
  <input class="search-box" value="how to know if my wifi dns is spoofed" readonly>
  <div class="btns">
    <button onclick="alert('Searching... Result: NetDecoy flagged your DNS as MALICIOUS!')">Google Search</button>
    <button onclick="alert('Congratulations! You were fooled by a rogue DNS sinkhole!')">I\'m Feeling Bamboozled</button>
  </div>
  <div class="sarcasm-card">
    <h3 style="color:#f87171; margin-bottom:8px;">🚨 DNS HIJACK ACTIVE!</h3>
    <p style="font-size:13px; color:#cbd5e1; margin:0; line-height:1.5;">
      You typed <strong>{html.escape(host)}</strong>, but you are looking at a decoy running on a laptop!
      A rogue attacker could have replaced this with a credential-harvesting phishing portal.
      <strong>NetDecoy catches this DNS divergence immediately!</strong>
    </p>
  </div>
</body>
</html>
"""


def _render_bank(host: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Totally Real Bank — Secure Login</title>
  <style>
    body {{
      font-family: -apple-system, sans-serif;
      background: #0f172a;
      color: #f8fafc;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      padding: 20px;
    }}
    .card {{
      background: #1e293b;
      border: 2px solid #ef4444;
      border-radius: 16px;
      padding: 32px;
      max-width: 420px;
      width: 100%;
      text-align: center;
      box-shadow: 0 10px 40px rgba(239, 68, 68, 0.2);
    }}
    input {{
      width: 100%;
      padding: 11px;
      margin: 8px 0;
      box-sizing: border-box;
      background: #0f172a;
      border: 1px solid #334155;
      color: #fff;
      border-radius: 8px;
    }}
    button {{
      width: 100%;
      padding: 12px;
      background: #ef4444;
      color: #fff;
      font-weight: 700;
      border: 0;
      border-radius: 8px;
      margin-top: 10px;
      cursor: pointer;
    }}
  </style>
</head>
<body>
  <div class="card">
    <div style="font-size:40px; margin-bottom:10px;">🏦</div>
    <h2>Totally Real Online Banking</h2>
    <p style="color:#94a3b8; font-size:13px; margin-bottom:20px;">
      Target: <code>{html.escape(host)}</code>
    </p>
    <div style="background:#450a0a; border:1px solid #991b1b; padding:12px; border-radius:8px; font-size:12px; color:#fca5a5; margin-bottom:18px;">
      ⚠️ SINKHOLE SIMULATION: In a real rogue AP attack, this would be an exact clone of your net-banking portal!
    </div>
    <form onsubmit="event.preventDefault(); alert('🎣 Credential Harvesting Blocked! NetDecoy detects DNS divergence before you log in.');">
      <input type="text" placeholder="Customer ID / Username" required>
      <input type="password" placeholder="NetBanking Password / OTP" required>
      <button type="submit">Log In to Fake Bank</button>
    </form>
  </div>
</body>
</html>
"""


def _render_generic(host: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NetDecoy — Spoofed Domain Decoy</title>
  <style>
    body {{
      font-family: system-ui, sans-serif;
      background: #070d18;
      color: #f8fafc;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      padding: 20px;
    }}
    .card {{
      background: #0f172a;
      border: 2px solid #38bdf8;
      border-radius: 18px;
      padding: 32px;
      max-width: 480px;
      width: 100%;
      text-align: center;
      box-shadow: 0 10px 40px rgba(56, 189, 248, 0.2);
    }}
    h1 {{ font-size: 26px; margin-bottom: 8px; }}
    .sub {{ color: #38bdf8; font-weight: 700; margin-bottom: 18px; font-size: 15px; }}
    p {{ font-size: 14px; color: #94a3b8; line-height: 1.6; }}
    .code-box {{
      background: #070d18;
      border: 1px solid #1e293b;
      padding: 14px;
      border-radius: 10px;
      margin: 18px 0;
      font-family: monospace;
      font-size: 13px;
      color: #f43f5e;
    }}
  </style>
</head>
<body>
  <div class="card">
    <div style="font-size:42px; margin-bottom:8px;">🎣</div>
    <h1>You've Been Bamboozled!</h1>
    <div class="sub">Rogue DNS Interception Successful</div>
    <p>
      You entered <strong style="color:#fff;">{html.escape(host)}</strong>, but the active Wi-Fi router's DNS resolver spoofed the lookup and pointed you straight to this decoy laptop!
    </p>
    <div class="code-box">
      HTTP Host: {html.escape(host)}<br>
      Verdict: SPOOFED BY NETDECOY HARNESS
    </div>
    <p style="font-size:12px; color:#64748b;">
      NetDecoy protects your device against this attack by validating all canaries through encrypted DNS-over-HTTPS (DoH).
    </p>
  </div>
</body>
</html>
"""
