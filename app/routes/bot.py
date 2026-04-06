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


async def answer_callback(callback_id: str, text: str = "") -> None:
    """Answer a callback query to dismiss the loading spinner."""
    async with httpx.AsyncClient() as client:
        await client.post(
            _api_url("answerCallbackQuery"),
            json={"callback_query_id": callback_id, "text": text},
            timeout=5.0,
        )


# ---------------------------------------------------------------------------
# Inline keyboards
# ---------------------------------------------------------------------------

def main_keyboard() -> dict:
    return {
        "inline_keyboard": [
            [{"text": "🔑 Generate Config", "callback_data": "gen"}],
            [{"text": "📱 V2BOX Subscription", "callback_data": "v2sub"}],
            [{"text": "ℹ️ Help", "callback_data": "help"}],
        ]
    }


def port_keyboard() -> dict:
    return {
        "inline_keyboard": [
            [
                {"text": "500 (Default)", "callback_data": "port_500"},
                {"text": "2408", "callback_data": "port_2408"},
            ],
            [
                {"text": "1701", "callback_data": "port_1701"},
                {"text": "4500", "callback_data": "port_4500"},
            ],
        ]
    }


def after_keyboard() -> dict:
    return {
        "inline_keyboard": [
            [{"text": "🔑 Generate Again", "callback_data": "gen"}],
            [{"text": "🏠 Main Menu", "callback_data": "menu"}],
        ]
    }


# ---------------------------------------------------------------------------
# Message templates (bilingual EN + MY)
# ---------------------------------------------------------------------------

WELCOME_TEXT = (
    "🛡️ <b>WarpGen Bot</b>\n\n"
    "Generate free Cloudflare WARP (WireGuard) configs instantly!\n"
    "Cloudflare WARP VPN config ကို အခမဲ့ ထုတ်ပေးပါတယ်!\n\n"
    "<b>Features:</b>\n"
    "• Fresh WARP identity per generation\n"
    "• WireGuard .conf file download\n"
    "• QR Code for mobile scanning\n"
    "• V2BOX / v2rayNG subscription link\n\n"
    "👇 Tap a button below to get started"
)

HELP_TEXT = (
    "ℹ️ <b>WarpGen Bot — Help</b>\n\n"
    "<b>Commands:</b>\n"
    "/start — Show main menu\n"
    "/generate — Quick generate (port 500)\n"
    "/help — Show this help message\n\n"
    "<b>How it works:</b>\n"
    "1. Tap 🔑 <b>Generate Config</b>\n"
    "2. Choose your preferred port\n"
    "3. Receive .conf file + QR code\n\n"
    "<b>Ports:</b>\n"
    "• <code>500</code> — Default (recommended)\n"
    "• <code>2408</code> — Alternative\n"
    "• <code>1701</code> — L2TP port\n"
    "• <code>4500</code> — IPSec NAT-T\n\n"
    "📌 Config works with WireGuard, v2rayNG, V2BOX,\n"
    "Amnezia VPN, NekoBox, and more."
)

PORT_SELECT_TEXT = (
    "🔧 <b>Select Port</b>\n"
    "Port ရွေးပါ:"
)

GENERATING_TEXT = (
    "⏳ Generating WARP config on port <code>{port}</code>…\n"
    "Cloudflare နဲ့ ချိတ်ဆက်နေပါတယ်…"
)

V2SUB_TEXT = (
    "📱 <b>V2BOX Subscription</b>\n\n"
    "Your permanent subscription URL:\n"
    "<code>{url}</code>\n\n"
    "<b>How to use:</b>\n"
    "1. Copy the URL above\n"
    "2. In V2BOX → Subscription → Add\n"
    "3. Paste the URL and save\n\n"
    "Every sync generates a brand new WARP identity! 🔄\n\n"
    "⚠️ <i>iOS V2BOX is currently not supported.</i>"
)


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

async def handle_start(chat_id: int) -> None:
    await send_message(chat_id, WELCOME_TEXT, reply_markup=main_keyboard())


async def handle_help(chat_id: int) -> None:
    await send_message(chat_id, HELP_TEXT, reply_markup=main_keyboard())


async def handle_port_select(chat_id: int) -> None:
    await send_message(chat_id, PORT_SELECT_TEXT, reply_markup=port_keyboard())


async def handle_generate(chat_id: int, port: int = 500) -> None:
    """Generate WARP config → send .conf file + QR code."""
    await send_message(chat_id, GENERATING_TEXT.format(port=port))

    try:
        target_ip = settings.known_warp_ips[0]
        result = await generate_warp(target_ip, port)
        await increment_stats()

        # 1) Send .conf file
        conf_bytes = result["conf"].encode("utf-8")
        endpoint = result["endpoint"]
        safe_name = endpoint.replace(":", "-")
        await send_document(
            chat_id,
            filename=f"warp-{safe_name}.conf",
            content=conf_bytes,
            caption=(
                f"✅ <b>WARP Config Generated!</b>\n\n"
                f"📍 Endpoint: <code>{endpoint}</code>\n\n"
                f"WireGuard, v2rayNG, V2BOX, Amnezia VPN\n"
                f"စသည်တို့နဲ့ သုံးနိုင်ပါတယ်။"
            ),
        )

        # 2) Send QR code image
        qr_bytes = base64.b64decode(result["qr"])
        await send_photo(
            chat_id,
            photo_bytes=qr_bytes,
            caption="📷 Scan with WireGuard app\nWireGuard app နဲ့ scan ဖတ်ပါ",
        )

        # 3) After-action menu
        await send_message(chat_id, "👆 Config ready! What next?", reply_markup=after_keyboard())

        logger.info("bot_generate_ok", chat_id=chat_id, endpoint=endpoint)

    except Exception as exc:
        logger.error("bot_generate_fail", chat_id=chat_id, error=str(exc))
        await send_message(
            chat_id,
            f"❌ <b>Generation failed</b>\n\n<code>{exc}</code>\n\nPlease try again.",
            reply_markup=after_keyboard(),
        )


async def handle_v2sub(chat_id: int) -> None:
    """Send V2BOX subscription link using chat_id as stable sub ID."""
    if not settings.app_url:
        await send_message(
            chat_id,
            "⚠️ V2BOX subscription requires <code>APP_URL</code> to be configured by the admin.",
            reply_markup=main_keyboard(),
        )
        return

    sub_id = f"tg-{chat_id}"
    sub_url = f"{settings.app_url.rstrip('/')}/api/v2sub/{sub_id}"
    await send_message(chat_id, V2SUB_TEXT.format(url=sub_url), reply_markup=after_keyboard())


# ---------------------------------------------------------------------------
# FastAPI routes
# ---------------------------------------------------------------------------

@router.post("")
async def telegram_webhook(request: Request) -> JSONResponse:
    """Receive Telegram webhook updates and dispatch to handlers."""
    if not settings.telegram_bot_token:
        return JSONResponse({"error": "Bot token not configured"}, status_code=503)

    try:
        update = await request.json()
        logger.info("bot_update", update_id=update.get("update_id"))

        # --- Callback queries (inline button presses) ---
        if "callback_query" in update:
            cb = update["callback_query"]
            cb_id = cb["id"]
            chat_id = cb["message"]["chat"]["id"]
            data = cb.get("data", "")

            await answer_callback(cb_id)

            if data == "gen":
                await handle_port_select(chat_id)
            elif data.startswith("port_"):
                port = int(data.split("_")[1])
                await handle_generate(chat_id, port)
            elif data == "v2sub":
                await handle_v2sub(chat_id)
            elif data == "help":
                await handle_help(chat_id)
            elif data == "menu":
                await handle_start(chat_id)

        # --- Text messages ---
        elif "message" in update:
            msg = update["message"]
            chat_id = msg["chat"]["id"]
            text = (msg.get("text") or "").strip()

            if text == "/start":
                await handle_start(chat_id)
            elif text == "/generate":
                await handle_generate(chat_id, port=500)
            elif text == "/help":
                await handle_help(chat_id)
            else:
                await send_message(
                    chat_id,
                    "🤔 Unknown command. Tap /start to see the menu.",
                    reply_markup=main_keyboard(),
                )

    except Exception as exc:
        logger.error("bot_webhook_error", error=str(exc))

    # Always return 200 to prevent Telegram from retrying
    return JSONResponse({"ok": True})


@router.get("/setup")
async def setup_webhook() -> dict:
    """One-time: register the webhook URL + bot commands with Telegram."""
    if not settings.telegram_bot_token:
        return {"error": "TELEGRAM_BOT_TOKEN not set in .env"}
    if not settings.app_url:
        return {"error": "APP_URL not set in .env"}

    webhook_url = f"{settings.app_url.rstrip('/')}/api/bot"

    async with httpx.AsyncClient() as client:
        # Register webhook
        resp = await client.post(
            _api_url("setWebhook"),
            json={
                "url": webhook_url,
                "allowed_updates": ["message", "callback_query"],
            },
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
