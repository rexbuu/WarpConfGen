import base64
from collections import defaultdict, deque
import io
import ipaddress
import json
import os
import socket
from threading import Lock
import time
import urllib.parse
from datetime import datetime, timezone

import qrcode
import requests
from dotenv import load_dotenv
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from nacl.public import PrivateKey

load_dotenv()

# --- Configuration ---
KNOWN_WARP_IPS = [
    "162.159.192.1", "162.159.192.2", "162.159.192.3",
    "162.159.193.1", "162.159.193.2", "162.159.193.3",
    "188.114.96.1", "188.114.97.1",
]
PEER_PUBLIC_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
STATS_FILE = os.getenv("STATS_FILE", "warpgen_stats.json")

app = FastAPI(title="WARP Generator")

# --- Rate Limiting ---
RATE_LIMIT_WINDOW_SECONDS = 60
_rate_limit_lock = Lock()
_rate_limit_buckets = defaultdict(deque)

# --- Stats Management ---
_stats_lock = Lock()

def _load_stats():
    defaults = {"total_generations": 0}
    try:
        if os.path.exists(STATS_FILE):
            with open(STATS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return defaults

def _save_stats(stats):
    try:
        with open(STATS_FILE, "w", encoding="utf-8") as f:
            json.dump(stats, f)
    except Exception:
        pass

def get_supabase_stats():
    if not SUPABASE_URL or not SUPABASE_KEY:
        return None
    try:
        headers = {"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"}
        resp = requests.get(f"{SUPABASE_URL}/rest/v1/stats?id=eq.1", headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data:
                return int(data[0].get("total_generations", 0))
    except Exception:
        pass
    return None

def increment_stats():
    with _stats_lock:
        stats = _load_stats()
        stats["total_generations"] = stats.get("total_generations", 0) + 1
        _save_stats(stats)
        
    if SUPABASE_URL and SUPABASE_KEY:
        try:
            headers = {
                "apikey": SUPABASE_KEY, 
                "Authorization": f"Bearer {SUPABASE_KEY}",
                "Content-Type": "application/json",
                "Prefer": "return=minimal"
            }
            # RPC call is cleaner for increments, but simple update works if row exists
            # This assumes a table 'stats' with id 1 exists.
            requests.post(
                f"{SUPABASE_URL}/rest/v1/rpc/increment_gen_count", 
                headers=headers, 
                timeout=5
            )
        except Exception:
            pass

# --- Core Logic ---
def get_client_ip(request: Request):
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

@app.middleware("http")
async def rate_limit(request: Request, call_next):
    if request.url.path not in ["/", "/generate"]:
        return await call_next(request)
    
    client_ip = get_client_ip(request)
    now = time.time()
    with _rate_limit_lock:
        bucket = _rate_limit_buckets[client_ip]
        while bucket and bucket[0] <= now - RATE_LIMIT_WINDOW_SECONDS:
            bucket.popleft()
        if len(bucket) >= 10: # 10 requests per minute
            return PlainTextResponse("Too many requests", status_code=429)
        bucket.append(now)
    return await call_next(request)

def probe_udp(ip, port, timeout=1.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.send(b"\x00")
            return True
    except Exception:
        return False

def generate_warp(ip, port):
    priv = PrivateKey.generate()
    pub_b64 = base64.b64encode(bytes(priv.public_key)).decode()
    priv_b64 = base64.b64encode(bytes(priv)).decode()

    resp = requests.post(
        "https://api.cloudflareclient.com/v0a1925/reg",
        json={"key": pub_b64, "warp_enabled": True, "tos": "2024-01-01T00:00:00.000Z", "type": "Android", "locale": "en_US"},
        headers={"User-Agent": "okhttp/3.12.1"},
        timeout=15
    )
    resp.raise_for_status()
    data = resp.json()
    
    addr = data["config"]["interface"]["addresses"]
    v4, v6 = addr.get("v4", "172.16.0.2/32"), addr.get("v6", "")
    conf = f"[Interface]\nPrivateKey = {priv_b64}\nAddress = {v4}{', ' + v6 if v6 else ''}\nDNS = 1.1.1.1, 1.0.0.1\n\n[Peer]\nPublicKey = {PEER_PUBLIC_KEY}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {ip}:{port}\nPersistentKeepalive = 25\n"
    
    qr = qrcode.make(conf)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    return {"conf": conf, "qr": base64.b64encode(buf.getvalue()).decode(), "endpoint": f"{ip}:{port}"}

# --- UI Templates ---
def get_html(content="", mode="auto", selected_ip="", custom_ip="", port=500):
    supabase_count = get_supabase_stats()
    local_count = _load_stats()["total_generations"]
    display_count = supabase_count if supabase_count is not None else local_count

    # UI Definitions according to Clarity UI skill
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WarpGen - Modern WARP Generator</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
    <script src="https://unpkg.com/lucide@latest"></script>
    <style>
        :root {{
            --bg-page: #f0ece4;
            --bg-card: rgba(255, 255, 255, 0.55);
            --bg-card-hover: rgba(255, 255, 255, 0.75);
            --text-primary: #1a1a1a;
            --text-secondary: #6b6b6b;
            --accent: #e8a838;
            --accent-dark: #c48820;
            --border-glass: 1px solid rgba(255, 255, 255, 0.35);
            --shadow-card: 0 4px 24px rgba(0, 0, 0, 0.06);
            --radius-md: 16px;
            --radius-lg: 24px;
            --radius-full: 9999px;
            --space-md: 16px;
            --space-lg: 24px;
        }}

        * {{ box-sizing: border-box; outline: none; }}
        body {{
            font-family: 'Outfit', sans-serif;
            background: var(--bg-page);
            color: var(--text-primary);
            margin: 0;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            overflow-x: hidden;
            line-height: 1.5;
        }}

        body::before, body::after {{
            content: '';
            position: fixed;
            border-radius: 50%;
            filter: blur(80px);
            opacity: 0.25;
            z-index: -1;
        }}
        body::before {{ width: 500px; height: 500px; background: linear-gradient(135deg, #e8a838, #ffc8dd); top: -100px; right: -100px; }}
        body::after {{ width: 400px; height: 400px; background: linear-gradient(135deg, #bde0fe, #e8a838); bottom: -80px; left: -80px; }}

        .container {{
            max-width: 800px;
            margin: 40px auto;
            padding: 0 var(--space-md);
            width: 100%;
        }}

        .nav {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 32px;
        }}

        .logo {{ font-size: 24px; font-weight: 700; color: var(--accent); display: flex; align-items: center; gap: 8px; }}
        
        .lang-switch {{
            background: var(--bg-card);
            backdrop-filter: blur(16px);
            border: var(--border-glass);
            border-radius: var(--radius-full);
            padding: 4px;
            display: flex;
            gap: 4px;
            box-shadow: var(--shadow-card);
        }}

        .lang-btn {{
            border: none;
            background: transparent;
            padding: 6px 16px;
            border-radius: var(--radius-full);
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.2s ease;
            color: var(--text-secondary);
        }}

        .lang-btn.active {{
            background: white;
            color: var(--accent);
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }}

        .card {{
            background: var(--bg-card);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: var(--border-glass);
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow-card);
            padding: var(--space-lg);
            margin-bottom: var(--space-lg);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }}

        .hero {{ text-align: center; margin-bottom: 48px; }}
        .hero h1 {{ font-size: 48px; margin: 0 0 8px 0; letter-spacing: -0.02em; }}
        .hero p {{ font-size: 18px; color: var(--text-secondary); margin: 0; }}

        .stats-badge {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(232, 168, 56, 0.1);
            color: var(--accent-dark);
            padding: 6px 16px;
            border-radius: var(--radius-full);
            font-weight: 600;
            font-size: 14px;
            margin-top: 16px;
        }}

        .form-group {{ margin-bottom: 20px; }}
        label {{ display: block; font-weight: 600; margin-bottom: 8px; font-size: 15px; color: var(--text-primary); }}
        
        input, select {{
            width: 100%;
            padding: 12px 16px;
            border-radius: var(--radius-md);
            border: 1px solid rgba(0,0,0,0.08);
            background: rgba(255,255,255,0.8);
            font-family: inherit;
            font-size: 16px;
            transition: all 0.2s ease;
        }}

        input:focus {{ border-color: var(--accent); border-width: 1.5px; }}

        .radio-group {{ display: flex; gap: 12px; flex-wrap: wrap; }}
        .radio-item {{
            flex: 1;
            min-width: 120px;
            position: relative;
        }}
        .radio-item input {{ position: absolute; opacity: 0; cursor: pointer; }}
        .radio-label {{
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 16px;
            background: rgba(255,255,255,0.5);
            border: 1px solid rgba(0,0,0,0.05);
            border-radius: var(--radius-md);
            cursor: pointer;
            transition: all 0.2s ease;
            text-align: center;
        }}
        .radio-item input:checked + .radio-label {{
            background: white;
            border-color: var(--accent);
            box-shadow: 0 4px 12px rgba(232, 168, 56, 0.15);
            color: var(--accent-dark);
        }}
        .radio-item i {{ margin-bottom: 8px; color: var(--text-secondary); }}
        .radio-item input:checked + .radio-label i {{ color: var(--accent); }}

        .btn-primary {{
            width: 100%;
            background: var(--accent);
            color: white;
            border: none;
            border-radius: var(--radius-full);
            padding: 16px;
            font-size: 18px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            box-shadow: 0 4px 12px rgba(232, 168, 56, 0.3);
            margin-top: 10px;
        }}
        .btn-primary:hover {{ background: var(--accent-dark); transform: translateY(-2px); }}
        .btn-primary:active {{ transform: scale(0.98); }}

        .output-section {{
            animation: slideUp 0.5s ease-out;
            text-align: center;
        }}
        @keyframes slideUp {{ from {{ opacity: 0; transform: translateY(20px); }} to {{ opacity: 1; transform: translateY(0); }} }}

        .qr-card {{
            background: white;
            padding: 24px;
            border-radius: var(--radius-lg);
            display: inline-block;
            margin-bottom: 24px;
            box-shadow: var(--shadow-card);
        }}
        .qr-card img {{ max-width: 250px; width: 100%; height: auto; }}

        .btn-group {{ display: flex; gap: 12px; justify-content: center; }}
        .btn-outline {{
            background: transparent;
            border: 1.5px solid var(--accent);
            color: var(--accent);
            padding: 10px 24px;
            border-radius: var(--radius-full);
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.2s ease;
        }}
        .btn-outline:hover {{ background: var(--accent); color: white; }}

        .config-code {{
            background: #1a1a1a;
            color: #d1d1d1;
            padding: 24px;
            border-radius: var(--radius-md);
            font-family: 'DM Mono', monospace;
            font-size: 14px;
            text-align: left;
            overflow-x: auto;
            position: relative;
            margin-top: 24px;
        }}

        .instructions {{ margin-top: 48px; }}
        .instructions h2 {{ display: flex; align-items: center; gap: 10px; margin-top: 32px; }}
        .step-list {{ list-style: none; padding: 0; }}
        .step-item {{
            display: flex;
            gap: 16px;
            margin-bottom: 20px;
            align-items: flex-start;
        }}
        .step-num {{
            background: var(--accent);
            color: white;
            width: 28px;
            height: 28px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            font-weight: 700;
            flex-shrink: 0;
            margin-top: 2px;
        }}

        .footer-link {{
            display: flex;
            align-items: center;
            gap: 8px;
            color: var(--text-secondary);
            text-decoration: none;
            font-weight: 600;
            font-size: 14px;
            transition: all 0.2s ease;
        }}
        .footer-link:hover {{
            color: var(--accent);
            transform: translateY(-1px);
        }}

        footer {{ margin-top: auto; padding: 40px 0; text-align: center; border-top: var(--border-glass); }}

        
        .hidden {{ display: none; }}

        @media (max-width: 640px) {{
            .hero h1 {{ font-size: 36px; }}
            .radio-group {{ flex-direction: column; }}
            .btn-group {{ flex-direction: column; }}
            .container {{ margin: 20px auto; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <nav class="nav">
            <div class="logo"><i data-lucide="shield-check"></i> WarpGen</div>
            <div class="lang-switch">
                <button class="lang-btn active" onclick="setLang('en')">EN</button>
                <button class="lang-btn" onclick="setLang('mm')">MM</button>
            </div>
        </nav>

        <header class="hero">
            <h1 data-t="title">Fast & Secure</h1>
            <p data-t="subtitle">Cloudflare WARP Configuration Generator</p>
            <div class="stats-badge">
                <i data-lucide="trending-up" size="16"></i>
                <span data-t="gen-count">Total Generations:</span> {display_count}
            </div>
        </header>

        <main>
            <section class="card">
                <form id="genForm" method="POST" action="/generate">
                    <div class="form-group">
                        <label data-t="ip-mode">Endpoint IP Mode</label>
                        <div class="radio-group">
                            <div class="radio-item">
                                <input type="radio" name="mode" id="mode-auto" value="auto" {"checked" if mode=="auto" else ""}>
                                <label for="mode-auto" class="radio-label">
                                    <i data-lucide="zap"></i>
                                    <span data-t="mode-auto">Auto Select</span>
                                </label>
                            </div>
                            <div class="radio-item">
                                <input type="radio" name="mode" id="mode-select" value="select" {"checked" if mode=="select" else ""}>
                                <label for="mode-select" class="radio-label">
                                    <i data-lucide="list"></i>
                                    <span data-t="mode-select">From List</span>
                                </label>
                            </div>
                            <div class="radio-item">
                                <input type="radio" name="mode" id="mode-custom" value="custom" {"checked" if mode=="custom" else ""}>
                                <label for="mode-custom" class="radio-label">
                                    <i data-lucide="edit-3"></i>
                                    <span data-t="mode-custom">Custom IP</span>
                                </label>
                            </div>
                        </div>
                    </div>

                    <div id="select-box" class="form-group {"hidden" if mode!="select" else ""}">
                        <label data-t="choose-ip">Choose available IP</label>
                        <select name="selected_ip">
                            {"".join([f"<option value='{ip}' {'selected' if selected_ip==ip else ''}>{ip}</option>" for ip in KNOWN_WARP_IPS])}
                        </select>
                    </div>

                    <div id="custom-box" class="form-group {"hidden" if mode!="custom" else ""}">
                        <label data-t="enter-ip">Enter Custom Endpoint IP</label>
                        <input type="text" name="custom_ip" value="{custom_ip}" placeholder="e.g. 162.159.192.1">
                    </div>

                    <div class="form-group">
                        <label data-t="port">Port</label>
                        <input type="number" name="port" value="{port}" min="1" max="65535">
                    </div>

                    <button type="submit" class="btn-primary">
                        <i data-lucide="refresh-cw"></i>
                        <span data-t="btn-generate">Generate Config</span>
                    </button>
                </form>
            </section>

            {content}

            <section class="instructions">
                <h2 data-t="how-to-use"><i data-lucide="info"></i> How to Use</h2>
                <div class="card">
                    <ul class="step-list">
                        <li class="step-item">
                            <div class="step-num">1</div>
                            <div>
                                <strong data-t="s1-t">Set Options</strong><br>
                                <span data-t="s1-d">Choose between automatic IP selection or enter your favorite Cloudflare endpoint IP and port.</span>
                            </div>
                        </li>
                        <li class="step-item">
                            <div class="step-num">2</div>
                            <div>
                                <strong data-t="s2-t">Click Generate</strong><br>
                                <span data-t="s2-d">Hit the generate button. It will create a unique Private Key and register it with Cloudflare.</span>
                            </div>
                        </li>
                        <li class="step-item">
                            <div class="step-num">3</div>
                            <div>
                                <strong data-t="s3-t">Save Result</strong><br>
                                <span data-t="s3-d">Download the .conf file for PC or scan the QR code with your WireGuard mobile app.</span>
                            </div>
                        </li>
                    </ul>
                </div>

                <h2 data-t="how-to-connect"><i data-lucide="link"></i> How to Connect</h2>
                <div class="card">
                    <p data-t="connect-desc">WARP uses the WireGuard protocol. You can use this config in any WireGuard client.</p>
                    <ul class="step-list">
                        <li class="step-item">
                            <i data-lucide="smartphone" style="margin-top:4px"></i>
                            <div>
                                <strong data-t="c-mob">Android & iOS</strong><br>
                                <span data-t="c-mob-d">Download 'WireGuard' from Store. Tap (+) and 'Scan from QR code'.</span>
                            </div>
                        </li>
                        <li class="step-item">
                            <i data-lucide="monitor" style="margin-top:4px"></i>
                            <div>
                                <strong data-t="c-pc">Windows & Mac</strong><br>
                                <span data-t="c-pc-d">Install 'WireGuard' and 'Add Tunnel' -> Import from file (.conf).</span>
                            </div>
                        </li>
                    </ul>
                </div>
            </section>
        </main>

        <footer>
            <p>&copy; 2026 WarpGen. Made for educational purposes.</p>
            <div style="display:flex; justify-content:center; align-items:center; gap:24px; margin-top:16px; flex-wrap:wrap;">
                <a href="https://t.me/BadCodeWriter" target="_blank" class="footer-link">
                    <i data-lucide="message-circle"></i>
                    <span data-t="f-contact">Contact</span>
                </a>
                <a href="https://t.me/h3lpw1thvpn" target="_blank" class="footer-link">
                    <i data-lucide="users"></i>
                    <span data-t="f-group">Telegram Group</span>
                </a>
                <a href="https://github.com/devtint/WarpConfGen" target="_blank" class="footer-link">
                    <i data-lucide="github"></i>
                    <span data-t="f-github">GitHub</span>
                </a>
            </div>
        </footer>
    </div>

    <script>
        lucide.createIcons();

        const translations = {{
            en: {{
                'title': 'Fast & Secure',
                'subtitle': 'Cloudflare WARP Configuration Generator',
                'gen-count': 'Total Generations:',
                'ip-mode': 'Endpoint IP Mode',
                'mode-auto': 'Auto Select',
                'mode-select': 'From List',
                'mode-custom': 'Custom IP',
                'choose-ip': 'Choose available IP',
                'enter-ip': 'Enter Custom Endpoint IP',
                'port': 'Port',
                'btn-generate': 'Generate Config',
                'how-to-use': 'How to Use',
                's1-t': 'Set Options',
                's1-d': 'Choose between automatic IP selection or enter your favorite Cloudflare endpoint IP and port.',
                's2-t': 'Click Generate',
                's2-d': 'Hit the generate button. It will create a unique Private Key and register it with Cloudflare.',
                's3-t': 'Save Result',
                's3-d': 'Download the .conf file for PC or scan the QR code with your WireGuard mobile app.',
                'how-to-connect': 'How to Connect',
                'connect-desc': 'WARP uses the WireGuard protocol. You can use this config in any WireGuard client.',
                'c-mob': 'Android & iOS',
                'c-mob-d': "Download 'WireGuard' from Store. Tap (+) and 'Scan from QR code'.",
                'c-pc': 'Windows & Mac',
                'c-pc-d': "Install 'WireGuard' and 'Add Tunnel' -> Import from file (.conf).",
                'f-contact': 'Contact',
                'f-group': 'Telegram Group',
                'f-github': 'GitHub'
            }},
            mm: {{
                'title': 'မြန်ဆန်ပြီး လုံခြုံသော',
                'subtitle': 'Cloudflare WARP Configuration ထုတ်ယူခြင်း',
                'gen-count': 'စုစုပေါင်း ထုတ်ယူမှုအရေအတွက် -',
                'ip-mode': 'Endpoint IP ရွေးချယ်မှု',
                'mode-auto': 'အလိုအလျောက်',
                'mode-select': 'စာရင်းထဲမှရွေးရန်',
                'mode-custom': 'ကိုယ်တိုင်ရိုက်ရန်',
                'choose-ip': 'ရရှိနိုင်သော IP ကိုရွေးပါ',
                'enter-ip': 'Custom Endpoint IP ရိုက်ထည့်ပါ',
                'port': 'Port နံပါတ်',
                'btn-generate': 'Config ထုတ်ယူမည်',
                'how-to-use': 'အသုံးပြုနည်း',
                's1-t': 'ရွေးချယ်မှုများ သတ်မှတ်ပါ',
                's1-d': 'အလိုအလျောက် IP ရွေးခိုင်းမည်လား သို့မဟုတ် သင်နှစ်သက်ရာ IP နှင့် Port ကို ရိုက်ထည့်မည်လား ရွေးချယ်ပါ။',
                's2-t': 'Generate နှိပ်ပါ',
                's2-d': 'Generate ခလုတ်ကိုနှိပ်ပါ။ သင့်အတွက်သီးသန့် Private Key တစ်ခုပြုလုပ်ပြီး Cloudflare တွင် မှတ်ပုံတင်ပေးပါလိမ့်မည်။',
                's3-t': 'သိမ်းဆည်းပါ',
                's3-d': 'ကွန်ပျူတာအတွက် .conf ဖိုင်ကို ဒေါင်းလုဒ်ဆွဲပါ သို့မဟုတ် ဖုန်းမှ WireGuard app ဖြင့် QR code ကို စကင်ဖတ်ပါ။',
                'how-to-connect': 'ချိတ်ဆက်နည်း',
                'connect-desc': 'WARP သည် WireGuard protocol ကိုအသုံးပြုထားသည်။ ၎င်းကို မည်သည့် WireGuard client တွင်မဆို အသုံးပြုနိုင်ပါသည်။',
                'c-mob': 'ဖုန်း (Android & iOS)',
                'c-mob-d': "Play Store သို့မဟုတ် App Store မှ 'WireGuard' ကို ဒေါင်းပါ။ (+) ကိုနှိပ်ပြီး 'Scan from QR code' ကိုရွေးပါ။",
                'c-pc': 'ကွန်ပျူတာ (Windows & Mac)',
                'c-pc-d': "'WireGuard' ကိုသွင်းပါ။ 'Add Tunnel' -> 'Import from file' မှ ဒေါင်းလုဒ်လုပ်ထားသော .conf ဖိုင်ကို ရွေးပေးပါ။",
                'f-contact': 'ဆက်သွယ်ရန်',
                'f-group': 'တယ်လီဂရမ်အုပ်စု',
                'f-github': 'GitHub'
            }}
        }};

        function setLang(lang) {{
            localStorage.setItem('pref_lang', lang);
            document.querySelectorAll('.lang-btn').forEach(b => {{
                b.classList.toggle('active', b.innerText.toLowerCase() === lang);
            }});
            
            document.querySelectorAll('[data-t]').forEach(el => {{
                const key = el.getAttribute('data-t');
                if (translations[lang][key]) {{
                    el.innerText = translations[lang][key];
                }}
            }});
        }}

        // Init Language
        const savedLang = localStorage.getItem('pref_lang') || 'en';
        setLang(savedLang);

        // UI Interactions
        document.querySelectorAll('input[name="mode"]').forEach(radio => {{
            radio.addEventListener('change', (e) => {{
                document.getElementById('select-box').classList.toggle('hidden', e.target.value !== 'select');
                document.getElementById('custom-box').classList.toggle('hidden', e.target.value !== 'custom');
            }});
        }});
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def index():
    return get_html()

@app.post("/generate", response_class=HTMLResponse)
def generate(
    mode: str = Form("auto"),
    selected_ip: str = Form(""),
    custom_ip: str = Form(""),
    port: int = Form(500)
):
    try:
        target_ip = ""
        if mode == "auto":
            # Just take the first known one for simplicity in this demo, 
            # ideally probe them or use Cloudflare engage IP
            target_ip = KNOWN_WARP_IPS[0]
        elif mode == "select":
            target_ip = selected_ip if selected_ip else KNOWN_WARP_IPS[0]
        else:
            target_ip = custom_ip.strip()
            if not target_ip: raise ValueError("Custom IP required")
            ipaddress.ip_address(target_ip)

        result = generate_warp(target_ip, port)
        increment_stats()
        
        content = f"""
        <section class="output-section">
            <div class="card">
                <h2 style="margin-top:0"><i data-lucide="check-circle" style="color:#059669"></i> Success!</h2>
                <div class="qr-card">
                    <img src="data:image/png;base64,{result['qr']}" alt="QR Config">
                </div>
                <div class="btn-group">
                    <a href="data:text/plain;charset=utf-8,{urllib.parse.quote(result['conf'])}" download="warp-{int(time.time())}.conf" class="btn-primary" style="padding:12px 32px; width:auto;">
                        <i data-lucide="download"></i> Download .conf
                    </a>
                </div>
                
                <div class="config-code">
                    <pre>{result['conf']}</pre>
                </div>
            </div>
        </section>
        """
        return get_html(content=content, mode=mode, selected_ip=selected_ip, custom_ip=custom_ip, port=port)
    except Exception as e:
        err_content = f"""<div class="card" style="border-color: #fee2e2; background: rgba(254,226,226,0.5);">
            <p style="color:#b91c1c; margin:0;"><strong>Error:</strong> {str(e)}</p>
        </div>"""
        return get_html(content=err_content, mode=mode, selected_ip=selected_ip, custom_ip=custom_ip, port=port)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)