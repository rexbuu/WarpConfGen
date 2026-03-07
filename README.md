# 🛡️ WarpGen

Modern FastAPI web app to generate Cloudflare WARP (WireGuard) VPN configurations — with a premium glassmorphism UI, Smart Scan, and Myanmar language support.

![Python](https://img.shields.io/badge/Python-3.12+-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-latest-009688?logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Deploy](https://img.shields.io/badge/Deploy-Vercel-black?logo=vercel)

---

## ✨ Features

- **Premium Glassmorphism UI** — Warm off-white palette, frosted glass cards, Outfit + DM Mono fonts, micro-animations
- **4 Endpoint Modes** — Default IPs, From List, Custom IP, Smart Scan
- **Smart Scan** — Live UDP probing of Cloudflare WARP CIDR ranges with **latency badges** (green/yellow/red)
- **Bilingual** — English + Myanmar (Burmese) language toggle
- **Config History** — Last 5 generated configs saved in localStorage for quick retrieval
- **QR Code Export** — Scan directly with WireGuard mobile app
- **Copy to Clipboard** — One-click config copy with toast notification
- **Download .conf** — Ready-to-import WireGuard configuration file
- **Port Selection** — Dropdown with common WARP ports (500, 2408, 1701, 4500)
- **Rate Limiting** — 15 requests per 60-second window per IP
- **Supabase Stats** — Global generation counter with local JSON fallback
- **Structured Logging** — JSON-structured logs via `structlog` (no more silent errors)
- **Async I/O** — Non-blocking Cloudflare API calls via `httpx`

---

## 🏗️ Architecture

```
WarpGen/
├── app/
│   ├── __init__.py              # App factory + structlog config
│   ├── config.py                # Pydantic Settings (typed, validated)
│   ├── routes/
│   │   ├── api.py               # POST /api/generate, GET /api/scan
│   │   └── pages.py             # GET / (Jinja2 template)
│   ├── services/
│   │   ├── warp.py              # Cloudflare registration (async httpx)
│   │   ├── scanner.py           # UDP probing with latency measurement
│   │   └── stats.py             # Local + Supabase stats tracking
│   └── middleware/
│       └── rate_limit.py        # Sliding-window rate limiter
├── templates/
│   └── index.html               # Jinja2 template (HTML/CSS/JS)
├── api/
│   └── index.py                 # Vercel serverless entry point
├── main.py                      # Local dev entry point
├── requirements.txt
├── vercel.json                  # Vercel deployment config
├── supabase_setup.sql           # Optional DB setup script
└── .env.example                 # Environment variable template
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.12+, FastAPI, Uvicorn |
| **HTTP Client** | httpx (async) |
| **Crypto** | PyNaCl (WireGuard key generation) |
| **Templates** | Jinja2 |
| **Config** | pydantic-settings |
| **Logging** | structlog |
| **UI** | Vanilla HTML/CSS/JS, Lucide Icons, Google Fonts |
| **Database** | Supabase (optional, for global stats) |
| **Deployment** | Vercel (serverless Python) |

---

## 🚀 Local Development

### Prerequisites

- Python 3.12+
- pip

### Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Configure environment (optional — for Supabase stats)
cp .env.example .env
# Edit .env with your Supabase credentials

# Run the dev server
python main.py
```

Open: **http://127.0.0.1:8000**

---

## ☁️ Vercel Deployment

### 1. Deploy

```bash
vercel --prod
```

### 2. Set Environment Variables

In **Vercel Dashboard → Project Settings → Environment Variables**, add:

| Variable | Description |
|----------|-------------|
| `SUPABASE_URL` | Your Supabase project URL |
| `SUPABASE_KEY` | Your Supabase anon/public key |

---

## 🗄️ Supabase Setup (Optional)

To enable the global generation counter:

1. Create a project on [Supabase](https://supabase.com)
2. Run the setup script in the **SQL Editor**:

```sql
-- Create stats table
CREATE TABLE IF NOT EXISTS stats (
  id int PRIMARY KEY,
  total_generations int DEFAULT 0
);

-- Insert initial row
INSERT INTO stats (id, total_generations)
VALUES (1, 0)
ON CONFLICT (id) DO NOTHING;

-- Create atomic increment function
CREATE OR REPLACE FUNCTION increment_gen_count()
RETURNS void AS $$
BEGIN
  UPDATE stats
  SET total_generations = total_generations + 1
  WHERE id = 1;
END;
$$ LANGUAGE plpgsql;
```

3. Add your `SUPABASE_URL` and `SUPABASE_KEY` to `.env` (local) or Vercel env vars (production).

---

## 🔌 API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Serves the WarpGen web UI |
| `POST` | `/api/generate` | Generate a WARP config (form data: `mode`, `selected_ip`, `custom_ip`, `port`) |
| `GET` | `/api/scan?port=500` | Scan for working WARP IPs with latency |

### Example: Generate via API

```bash
curl -X POST http://127.0.0.1:8000/api/generate \
  -d "mode=auto&port=500"
```

### Example: Scan via API

```bash
curl http://127.0.0.1:8000/api/scan?port=2408
```

Response:
```json
{
  "ips": [
    {"ip": "162.159.192.1", "latency_ms": 45.2},
    {"ip": "188.114.97.1", "latency_ms": 78.1}
  ]
}
```

---

## 🌐 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SUPABASE_URL` | *(empty)* | Supabase project URL |
| `SUPABASE_KEY` | *(empty)* | Supabase anon key |
| `STATS_FILE` | `warpgen_stats.json` | Local stats fallback file |

---

## 📝 License

MIT Licensed. This project is provided for educational purposes.

---

<p align="center">
  Made with ☕ by <a href="https://t.me/BadCodeWriter">@BadCodeWriter</a> · <a href="https://t.me/h3lpw1thvpn">Telegram Group</a>
</p>
