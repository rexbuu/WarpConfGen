"""WARP configuration generation via Cloudflare API (async with httpx)."""
from __future__ import annotations

import base64
import io
from typing import TypedDict

import httpx
import qrcode
import structlog
from nacl.public import PrivateKey

from app.config import settings

logger = structlog.get_logger()

CLOUDFLARE_REG_URL = "https://api.cloudflareclient.com/v0a1925/reg"

import urllib.parse

class WarpResult(TypedDict):
    conf: str
    qr: str
    endpoint: str
    uri: str


async def generate_warp(ip: str, port: int) -> WarpResult:
    """Generate a WARP WireGuard config by registering with Cloudflare."""
    priv = PrivateKey.generate()
    pub_b64 = base64.b64encode(bytes(priv.public_key)).decode()
    priv_b64 = base64.b64encode(bytes(priv)).decode()

    logger.info("warp_registration_started", endpoint_ip=ip, port=port)

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            CLOUDFLARE_REG_URL,
            json={
                "key": pub_b64,
                "warp_enabled": True,
                "tos": "2024-01-01T00:00:00.000Z",
                "type": "Android",
                "locale": "en_US",
            },
            headers={"User-Agent": "okhttp/3.12.1"},
            timeout=15.0,
        )
        resp.raise_for_status()

    data = resp.json()
    addr = data["config"]["interface"]["addresses"]
    v4 = addr.get("v4", "172.16.0.2/32")
    v6 = addr.get("v6", "")
    address_str = f"{v4}{', ' + v6 if v6 else ''}"

    conf = (
        f"[Interface]\n"
        f"PrivateKey = {priv_b64}\n"
        f"Address = {address_str}\n"
        f"DNS = 1.1.1.1, 1.0.0.1\n\n"
        f"[Peer]\n"
        f"PublicKey = {settings.peer_public_key}\n"
        f"AllowedIPs = 0.0.0.0/0, ::/0\n"
        f"Endpoint = {ip}:{port}\n"
        f"PersistentKeepalive = 25\n"
    )

    qr_img = qrcode.make(conf)
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    # Use the universal Cloudflare WARP peer public key directly for the URI to avoid environment corruption
    CF_PEER_PUBLIC_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
    
    uri = (
        f"wireguard://{urllib.parse.quote(priv_b64, safe='')}"
        f"@{ip}:{port}"
        f"?publickey={urllib.parse.quote(CF_PEER_PUBLIC_KEY, safe='')}"
        f"&address={urllib.parse.quote(address_str, safe='')}"
        f"&reserved=0,0,0"
        f"&mtu=1420"
        f"#{urllib.parse.quote(f'WarpGen {ip}', safe='')}"
    )

    logger.info("warp_registration_success", endpoint=f"{ip}:{port}")
    return WarpResult(conf=conf, qr=qr_b64, endpoint=f"{ip}:{port}", uri=uri)
