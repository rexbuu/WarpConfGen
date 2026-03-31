"""API routes for config generation and scanning."""
from __future__ import annotations

import ipaddress

import structlog
from fastapi import APIRouter, Form

from app.config import settings
from app.services.scanner import scan_all_working, smart_scan
from app.services.stats import increment_stats
from app.services.warp import generate_warp

logger = structlog.get_logger()

router = APIRouter(prefix="/api")


import base64
from fastapi.responses import PlainTextResponse

@router.get("/scan")
def api_scan(port: int = 500):
    """Scan for working WARP endpoint IPs with latency info."""
    results = scan_all_working(port=port)
    return {"ips": results}


@router.get("/sub", response_class=PlainTextResponse)
async def api_sub(port: int = 500):
    """Subscription endpoint (returns Base64 encoded wireguard:// URI)."""
    try:
        # Use simple fast IP for subscription generation
        target_ip = settings.known_warp_ips[0]
        logger.info("subscription_requested", ip=target_ip, port=port)
        result = await generate_warp(target_ip, port)
        await increment_stats()
        
        # V2ray clients expect Base64 encoded text
        sub_text = base64.b64encode(result["uri"].encode("utf-8")).decode("utf-8")
        return sub_text
    except Exception as exc:
        logger.error("subscription_failed", error=str(exc))
        return base64.b64encode(f"error: {str(exc)}".encode("utf-8")).decode("utf-8")


from app.services.subscription import get_v2_subscription, update_v2_subscription
import uuid

from datetime import datetime, timedelta

# In-memory cooldown tracker to prevent multiple Cloudflare registrations within seconds for the same sub_id
_sub_last_refresh: dict[str, datetime] = {}

@router.get("/v2sub/{sub_id}", response_class=PlainTextResponse)
async def api_v2_sub(sub_id: str):
    """Dynamic V2BOX subscription: Generates NEW config on every sync, then stores/serves it."""
    try:
        now = datetime.now()
        # Cooldown of 5 seconds per sub_id to avoid Cloudflare spam on accidental multiple taps
        last_time = _sub_last_refresh.get(sub_id)
        
        if last_time and now - last_time < timedelta(seconds=5):
            # Just serve the stored one from DB if hit again within 5 seconds
            stored_uri = await get_v2_subscription(sub_id)
            if stored_uri:
                return base64.b64encode(stored_uri.encode()).decode()

        # 1. Generate NEW Warp Config
        target_ip = settings.known_warp_ips[0]
        port = 500
        logger.info("v2_auto_refresh_via_get", sub_id=sub_id)
        result = await generate_warp(target_ip, port)
        await increment_stats()
        
        # 2. Save/Update in DB for this sub_id
        await update_v2_subscription(sub_id, result["uri"])
        
        # 3. Update cooldown
        _sub_last_refresh[sub_id] = now

        # 4. Return Base64 encoded URI for V2BOX/Shadowrocket
        return base64.b64encode(result["uri"].encode()).decode()
    except Exception as exc:
        logger.error("v2_subscription_auto_refresh_failed", sub_id=sub_id, error=str(exc))
        # Fallback to stored if possible
        try:
            stored_uri = await get_v2_subscription(sub_id)
            if stored_uri:
                return base64.b64encode(stored_uri.encode()).decode()
        except: pass
        return base64.b64encode(f"error: {str(exc)}".encode()).decode()


@router.post("/v2sub/update")
async def api_v2_update(sub_id: str = Form(None)):
    """Refresh or create a V2BOX subscription: Generates new WARP and saves it."""
    try:
        # Use a new ID if none provided
        target_id = sub_id if sub_id else str(uuid.uuid4())
        
        # Use simple fast IP for registration
        target_ip = settings.known_warp_ips[0]
        port = 500
        
        logger.info("v2_refresh_requested", sub_id=target_id)
        result = await generate_warp(target_ip, port)
        await increment_stats()
        
        # Save to DB
        await update_v2_subscription(target_id, result["uri"])
        
        return {
            "sub_id": target_id,
            "url": f"/api/v2sub/{target_id}",
            "config": result
        }
    except Exception as exc:
        logger.error("v2_refresh_failed", error=str(exc))
        return {"error": str(exc)}


@router.post("/generate")
async def api_generate(
    mode: str = Form("auto"),
    selected_ip: str = Form(""),
    custom_ip: str = Form(""),
    port: int = Form(500),
):
    """Generate a WARP WireGuard configuration."""
    try:
        target_ip = ""
        if mode == "auto":
            target_ip = settings.known_warp_ips[0]
        elif mode == "smart":
            target_ip = smart_scan(port=port)
        elif mode == "select":
            target_ip = selected_ip if selected_ip else settings.known_warp_ips[0]
        else:
            target_ip = custom_ip.strip()
            if not target_ip:
                return {"error": "Custom IP required"}
            ipaddress.ip_address(target_ip)

        logger.info("generation_requested", mode=mode, ip=target_ip, port=port)
        result = await generate_warp(target_ip, port)
        await increment_stats()
        return result
    except ValueError as exc:
        logger.warning("invalid_ip_input", custom_ip=custom_ip, error=str(exc))
        return {"error": f"Invalid IP address: {custom_ip}"}
    except Exception as exc:
        logger.error("generation_failed", mode=mode, error=str(exc))
        return {"error": str(exc)}
