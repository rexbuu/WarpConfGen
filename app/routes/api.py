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


@router.get("/scan")
def api_scan(port: int = 500):
    """Scan for working WARP endpoint IPs with latency info."""
    results = scan_all_working(port=port)
    return {"ips": results}


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
