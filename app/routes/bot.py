"""Telegram bot webhook handler for WarpGen (zero-dependency, httpx only)."""
from __future__ import annotations

import base64
import io

import httpx
import structlog
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.config import settings
from app.services.stats import increment_stats
from app.services.warp import generate_warp

logger = structlog.get_logger()

router = APIRouter(prefix="/api/bot")


# ---------------------------------------------------------------------------
# Telegram Bot API helpers
# ---------------------------------------------------------------------------

def _api_url(method: str) -> str:
    """Build Telegram Bot API URL for a given method."""
    return f"https://api.telegram.org/bot{settings.telegram_bot_token}/{method}"


async def send_message(
    chat_id: int,
    text: str,
    reply_markup: dict | None = None,
    parse_mode: str = "HTML",
) -> None:
    """Send a text message via Telegram Bot API."""
    payload: dict = {"chat_id": chat_id, "text": text, "parse_mode": parse_mode}
    if reply_markup:
        payload["reply_markup"] = reply_markup

    async with httpx.AsyncClient() as client:
        resp = await client.post(_api_url("sendMessage"), json=payload, timeout=10.0)
        if resp.status_code != 200:
            logger.warning("tg_send_message_failed", status=resp.status_code, body=resp.text)


async def send_document(
    chat_id: int,
    filename: str,
    content: bytes,
    caption: str = "",
) -> None:
    """Send a file document via Telegram Bot API."""
    files = {"document": (filename, io.BytesIO(content), "application/octet-stream")}
    data: dict[str, str] = {"chat_id": str(chat_id)}
    if caption:
        data["caption"] = caption
        data["parse_mode"] = "HTML"

    async with httpx.AsyncClient() as client:
        resp = await client.post(_api_url("sendDocument"), data=data, files=files, timeout=15.0)
        if resp.status_code != 200:
            logger.warning("tg_send_document_failed", status=resp.status_code)


async def send_photo(
    chat_id: int,
    photo_bytes: bytes,
    caption: str = "",
) -> None:
    """Send a photo via Telegram Bot API."""
    files = {"photo": ("qrcode.png", io.BytesIO(photo_bytes), "image/png")}
    data: dict[str, str] = {"chat_id": str(chat_id)}
    if caption:
        data["caption"] = caption
        data["parse_mode"] = "HTML"

    async with httpx.AsyncClient() as client:
        resp = await client.post(_api_url("sendPhoto"), data=data, files=files, timeout=10.0)
        if resp.status_code != 200:
            logger.warning("tg_send_photo_failed", status=resp.status_code)


async def edit_message(
    chat_id: int,
    message_id: int,
    text: str,
    reply_markup: dict | None = None,
    parse_mode: str = "HTML",
) -> None:
    """Edit an existing message via Telegram Bot API."""
    payload: dict = {
        "chat_id": chat_id,
        "message_id": message_id,
        "text": text,
        "parse_mode": parse_mode,
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup

    async with httpx.AsyncClient() as client:
        await client.post(_api_url("editMessageText"), json=payload, timeout=10.0)


async def answer_callback(callback_id: str, text: str = "") -> None:
    """Answer a callback query to dismiss the loading spinner."""
    async with httpx.AsyncClient() as client:
        await client.post(
            _api_url("answerCallbackQuery"),
            json={"callback_query_id": callback_id, "text": text},
            timeout=5.0,
        )


# ---------------------------------------------------------------------------
# Inline keyboards & Message Templates
# ---------------------------------------------------------------------------

TEXTS = {
    "en": {
        "welcome": "🛡️ <b>WarpGen Bot</b>\n\nGenerate free Cloudflare WARP (WireGuard) configs instantly!\n\n<b>Features:</b>\n• Fresh WARP identity per generation\n• WireGuard .conf file\n• QR Code\n• V2BOX subscription link\n\n👇 Tap a button below to get started",
        "help": "ℹ️ <b>WarpGen Bot — Help</b>\n\n<b>Commands:</b>\n/start — Show main menu\n/generate — Quick generate (port 500)\n/help — Show this help message\n\n<b>How it works:</b>\n1. Tap 🔑 <b>Generate Config</b>\n2. Choose your preferred port\n3. Receive .conf file + QR code\n\n<b>Ports:</b>\n• <code>500</code> — Default (recommended)\n• <code>2408</code> — Alternative\n• <code>1701</code> — L2TP port\n• <code>4500</code> — IPSec NAT-T\n\n📌 Config works with WireGuard, v2rayNG, V2BOX, Amnezia VPN, NekoBox, and more.",
        "port": "🔧 <b>Select Port:</b>\nChoose a port for your Wireguard configuration:",
        "generating": "⏳ Generating WARP config on port <code>{port}</code>…",
        "v2sub": "📱 <b>V2BOX Subscription</b>\n\nYour permanent subscription URL:\n<code>{url}</code>\n\n<b>How to use:</b>\n1. Copy the URL above\n2. In V2BOX → Subscription → Add\n3. Paste the URL and save\n\nEvery sync generates a brand new WARP identity! 🔄\n\n⚠️ <i>iOS V2BOX is currently not supported.</i>",
        "success": "✅ <b>WARP Config Generated!</b>",
        "fail": "❌ <b>Generation failed</b>\n\n<code>{exc}</code>\n\nPlease try again.",
        "next": "👆 Config ready! What next?",
        "unknown": "🤔 Unknown command. Tap /start to see the menu.",
        "btn_gen": "🔑 Generate Config",
        "btn_again": "🔑 Generate Again",
        "btn_help": "ℹ️ Help",
        "btn_menu": "🏠 Main Menu",
        "btn_lang": "🇲🇲 Myanmar (မြန်မာ)",
    },
    "my": {
        "welcome": "🛡️ <b>WarpGen Bot</b>\n\nCloudflare WARP VPN config ကို အခမဲ့ ထုတ်ပေးပါတယ်!\n\n<b>ပါဝင်သောအရာများ:</b>\n• အသစ်ရယူတိုင်း WARP identity အသစ်ရမည်\n• WireGuard .conf file Download ချရန်\n• Mobile အတွက် QR Code\n• V2BOX / v2rayNG subscription link\n\n👇 အောက်ပါခလုတ်များကို နှိပ်ပါ။",
        "help": "ℹ️ <b>WarpGen Bot — အကူအညီ</b>\n\n<b>Commands:</b>\n/start — ပင်မစာမျက်နှာပြရန်\n/generate — အမြန်ထုတ်ရန် (port 500)\n/help — အကူအညီပြရန်\n\n<b>အသုံးပြုပုံ:</b>\n1. 🔑 <b>Config ထုတ်ရန်</b> ကိုနှိပ်ပါ\n2. လိုချင်သော Port ကိုရွေးပါ\n3. .conf file နှင့် QR code ကိုရရှိပါမည်။\n\n<b>Ports:</b>\n• <code>500</code> — မူလ (အကြံပြုပါသည်)\n• <code>2408</code> — အခြားရွေးချယ်စရာ\n• <code>1701</code> — L2TP port\n• <code>4500</code> — IPSec NAT-T\n\n📌 Config သည် WireGuard, v2rayNG, V2BOX, NekoBox စသည်တို့နဲ့ အသုံးပြုနိုင်ပါတယ်။",
        "port": "🔧 <b>Port ကို ရွေးချယ်ပါ:</b>",
        "generating": "⏳ WARP config ကို port <code>{port}</code> ဖြင့်ထုတ်လုပ်နေပါတယ်…\nCloudflare နဲ့ ချိတ်ဆက်နေပါတယ်…",
        "v2sub": "📱 <b>V2BOX Subscription</b>\n\nသင်၏ အမြဲတမ်းအသုံးပြုနိုင်သော URL:\n<code>{url}</code>\n\n<b>အသုံးပြုပုံ:</b>\n1. အထက်ပါ URL ကို copy ကူးပါ\n2. V2BOX → Subscription → Add တွင်ထည့်ပါ\n3. Save လုပ်ပါ\n\nUpdate လုပ်တိုင်း WARP အသစ်ရပါမည် 🔄\n\n⚠️ <i>iOS V2BOX တွင်လောလောဆယ် အဆင်မပြေသေးပါ။</i>",
        "success": "✅ <b>WARP Config ရရှိပါပြီ!</b>",
        "fail": "❌ <b>ထုတ်လုပ်မှု မအောင်မြင်ပါ</b>\n\n<code>{exc}</code>\n\nကျေးဇူးပြု၍ ပြန်စမ်းကြည့်ပါ။",
        "next": "👆 Config အဆင်သင့်ဖြစ်ပါပြီ! ဘာဆက်လုပ်မလဲ?",
        "unknown": "🤔 နားမလည်ပါ။ /start ကိုနှိပ်ပါ။",
        "btn_gen": "🔑 Config ထုတ်ရန်",
        "btn_again": "🔑 ထပ်မံထုတ်ရန်",
        "btn_help": "ℹ️ အကူအညီ",
        "btn_menu": "🏠 ပင်မသို့",
        "btn_lang": "🇬🇧 English",
    }
}


def main_keyboard(lang: str) -> dict:
    return {
        "inline_keyboard": [
            [{"text": TEXTS[lang]["btn_gen"], "callback_data": f"gen|{lang}"}],
            [{"text": "📱 V2BOX Subscription", "callback_data": f"v2sub|{lang}"}],
            [{"text": TEXTS[lang]["btn_help"], "callback_data": f"help|{lang}"}],
            [{"text": TEXTS[lang]["btn_lang"], "callback_data": f"lang|{'my' if lang == 'en' else 'en'}"}]
        ]
    }


def port_keyboard(lang: str) -> dict:
    return {
        "inline_keyboard": [
            [
                {"text": "500", "callback_data": f"port_500|{lang}"},
                {"text": "2408", "callback_data": f"port_2408|{lang}"},
            ],
            [
                {"text": "1701", "callback_data": f"port_1701|{lang}"},
                {"text": "4500", "callback_data": f"port_4500|{lang}"},
            ],
            [{"text": TEXTS[lang]["btn_menu"], "callback_data": f"menu|{lang}"}]
        ]
    }


def after_keyboard(lang: str) -> dict:
    return {
        "inline_keyboard": [
            [{"text": TEXTS[lang]["btn_again"], "callback_data": f"gen|{lang}"}],
            [{"text": TEXTS[lang]["btn_menu"], "callback_data": f"menu|{lang}"}],
        ]
    }


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

async def handle_start(chat_id: int, message_id: int = 0, lang: str = "en", is_edit: bool = False) -> None:
    text = TEXTS[lang]["welcome"]
    kb = main_keyboard(lang)
    if is_edit and message_id:
        await edit_message(chat_id, message_id, text, reply_markup=kb)
    else:
        await send_message(chat_id, text, reply_markup=kb)


async def handle_help(chat_id: int, message_id: int, lang: str) -> None:
    if message_id:
        await edit_message(chat_id, message_id, TEXTS[lang]["help"], reply_markup=main_keyboard(lang))
    else:
        await send_message(chat_id, TEXTS[lang]["help"], reply_markup=main_keyboard(lang))


async def handle_port_select(chat_id: int, message_id: int, lang: str) -> None:
    if message_id:
        await edit_message(chat_id, message_id, TEXTS[lang]["port"], reply_markup=port_keyboard(lang))
    else:
        await send_message(chat_id, TEXTS[lang]["port"], reply_markup=port_keyboard(lang))


async def handle_generate(chat_id: int, message_id: int, port: int, lang: str) -> None:
    if message_id:
        await edit_message(chat_id, message_id, TEXTS[lang]["generating"].format(port=port))
    else:
        await send_message(chat_id, TEXTS[lang]["generating"].format(port=port))

    try:
        target_ip = settings.known_warp_ips[0]
        result = await generate_warp(target_ip, port)
        await increment_stats()

        conf_str = result["conf"]
        endpoint = result["endpoint"]
        safe_name = endpoint.replace(":", "-")

        # 1) Send raw config text first for easy copying
        raw_msg = f"<code>\n{conf_str}</code>"
        await send_message(chat_id, raw_msg, parse_mode="HTML")

        # 2) Send .conf file
        await send_document(
            chat_id,
            filename="WarpGen.conf",
            content=conf_str.encode("utf-8"),
            caption=TEXTS[lang]["success"],
        )

        # 3) Send QR code image
        qr_bytes = base64.b64decode(result["qr"])
        await send_photo(
            chat_id,
            photo_bytes=qr_bytes,
            caption="📷 Scan with WireGuard app",
        )

        # 4) After-action menu
        await send_message(chat_id, TEXTS[lang]["next"], reply_markup=after_keyboard(lang))

        logger.info("bot_generate_ok", chat_id=chat_id, endpoint=endpoint)

    except Exception as exc:
        logger.error("bot_generate_fail", chat_id=chat_id, error=str(exc))
        await send_message(
            chat_id,
            TEXTS[lang]["fail"].format(exc=exc),
            reply_markup=after_keyboard(lang),
        )


async def handle_v2sub(chat_id: int, message_id: int, lang: str) -> None:
    if not settings.app_url:
        warn_text = "⚠️ <code>APP_URL</code> not set."
        if message_id:
            await edit_message(chat_id, message_id, warn_text, reply_markup=main_keyboard(lang))
        else:
            await send_message(chat_id, warn_text, reply_markup=main_keyboard(lang))
        return

    sub_id = f"tg-{chat_id}"
    sub_url = f"{settings.app_url.rstrip('/')}/api/v2sub/{sub_id}"
    
    if message_id:
        await edit_message(chat_id, message_id, TEXTS[lang]["v2sub"].format(url=sub_url), reply_markup=after_keyboard(lang))
    else:
        await send_message(chat_id, TEXTS[lang]["v2sub"].format(url=sub_url), reply_markup=after_keyboard(lang))


# ---------------------------------------------------------------------------
# FastAPI routes
# ---------------------------------------------------------------------------

@router.post("")
async def telegram_webhook(request: Request) -> JSONResponse:
    """Receive Telegram webhook updates and dispatch to handlers."""
    if not settings.telegram_bot_token:
        return JSONResponse({"error": "Bot token not configured"}, status_code=503)

    # Optional: Verify Telegram Secret Token (X-Telegram-Bot-Api-Secret-Token) if configured
    if settings.admin_secret:
        token = request.headers.get("X-Telegram-Bot-Api-Secret-Token")
        if token != settings.admin_secret:
            logger.warning("bot_unauthorized_access", token=token)
            return JSONResponse({"error": "Unauthorized Access (Secret Missing/Wrong)"}, status_code=403)

    try:
        update = await request.json()
        logger.info("bot_update", update_id=update.get("update_id"))

        # --- Callback queries (inline button presses) ---
        if "callback_query" in update:
            cb = update["callback_query"]
            cb_id = cb["id"]
            chat_id = cb["message"]["chat"]["id"]
            msg_id = cb["message"]["message_id"]
            raw_data = cb.get("data", "menu|en")

            # Parse action and language state from callback_data (e.g. "gen|my")
            parts = raw_data.split("|")
            action = parts[0]
            lang = parts[1] if len(parts) > 1 else "en"

            await answer_callback(cb_id)

            if action == "lang":
                # User clicked language toggle
                await handle_start(chat_id, msg_id, lang=lang, is_edit=True)
            elif action == "gen":
                await handle_port_select(chat_id, msg_id, lang)
            elif action.startswith("port_"):
                port = int(action.split("_")[1])
                await handle_generate(chat_id, msg_id, port, lang)
            elif action == "v2sub":
                await handle_v2sub(chat_id, msg_id, lang)
            elif action == "help":
                await handle_help(chat_id, msg_id, lang)
            elif action == "menu":
                await handle_start(chat_id, msg_id, lang, is_edit=True)

        # --- Text messages ---
        elif "message" in update:
            msg = update["message"]
            chat_id = msg["chat"]["id"]
            text = (msg.get("text") or "").strip()

            if text == "/start":
                await handle_start(chat_id, lang="en")
            elif text == "/generate":
                await handle_generate(chat_id, 0, port=500, lang="en")
            elif text == "/help":
                await handle_help(chat_id, 0, lang="en")
            else:
                await send_message(
                    chat_id,
                    TEXTS["en"]["unknown"],
                    reply_markup=main_keyboard("en"),
                )

    except Exception as exc:
        logger.error("bot_webhook_error", error=str(exc))

    # Always return 200 to prevent Telegram from retrying
    return JSONResponse({"ok": True})


@router.get("/setup")
async def setup_webhook(key: str = "") -> dict:
    """One-time: register the webhook URL + bot commands with Telegram."""
    if not settings.telegram_bot_token:
        return {"error": "TELEGRAM_BOT_TOKEN not set in .env"}
    if not settings.app_url:
        return {"error": "APP_URL not set in .env"}

    # Protection: /setup?key=YOUR_ADMIN_SECRET
    if settings.admin_secret and key != settings.admin_secret:
        return {"error": "Unauthorized Access (Key Missing/Wrong)"}

    webhook_url = f"{settings.app_url.rstrip('/')}/api/bot"

    async with httpx.AsyncClient() as client:
        # Register webhook with secret_token for header validation
        payload = {
            "url": webhook_url,
            "allowed_updates": ["message", "callback_query"],
        }
        if settings.admin_secret:
            payload["secret_token"] = settings.admin_secret

        resp = await client.post(
            _api_url("setWebhook"),
            json=payload,
            timeout=10.0,
        )
        webhook_result = resp.json()

        # Register bot commands menu
        await client.post(
            _api_url("setMyCommands"),
            json={
                "commands": [
                    {"command": "start", "description": "Show main menu"},
                    {"command": "generate", "description": "Generate WARP config"},
                    {"command": "help", "description": "Show help"},
                ]
            },
            timeout=10.0,
        )

    logger.info("bot_webhook_registered", url=webhook_url, result=webhook_result)
    return {"webhook_url": webhook_url, "telegram_response": webhook_result}
