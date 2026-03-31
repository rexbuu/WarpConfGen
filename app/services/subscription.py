"""Service for managing V2BOX compatible subscriptions in Supabase."""
from __future__ import annotations

import httpx
import structlog
from app.config import settings

logger = structlog.get_logger()

async def get_v2_subscription(sub_id: str) -> str | None:
    """Fetch the latest config URI for a given subscription ID."""
    if not settings.supabase_url or not settings.supabase_key:
        return None
    
    try:
        headers = {
            "apikey": settings.supabase_key,
            "Authorization": f"Bearer {settings.supabase_key}",
        }
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{settings.supabase_url}/rest/v1/v2_subscriptions?id=eq.{sub_id}",
                headers=headers,
                timeout=5.0,
            )
        if resp.status_code == 200:
            data = resp.json()
            if data:
                return data[0].get("config_uri")
    except Exception as exc:
        logger.warning("subscription_fetch_failed", sub_id=sub_id, error=str(exc))
    return None

async def update_v2_subscription(sub_id: str, uri: str) -> None:
    """Update or create a subscription entry in Supabase."""
    if not settings.supabase_url or not settings.supabase_key:
        return

    try:
        headers = {
            "apikey": settings.supabase_key,
            "Authorization": f"Bearer {settings.supabase_key}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal",
        }
        payload = {"p_id": sub_id, "p_uri": uri}
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{settings.supabase_url}/rest/v1/rpc/update_v2_subscription",
                headers=headers,
                json=payload,
                timeout=5.0,
            )
        logger.info("subscription_updated", sub_id=sub_id)
    except Exception as exc:
        logger.error("subscription_update_failed", sub_id=sub_id, error=str(exc))
