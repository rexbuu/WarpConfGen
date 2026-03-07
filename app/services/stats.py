"""Generation statistics tracking (local file + Supabase) with structured logging."""
from __future__ import annotations

import json
import os
from threading import Lock

import httpx
import structlog

from app.config import settings

logger = structlog.get_logger()

_stats_lock = Lock()


def _load_stats() -> dict:
    """Load stats from local JSON file."""
    defaults = {"total_generations": 0}
    try:
        if os.path.exists(settings.stats_file):
            with open(settings.stats_file, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as exc:
        logger.warning("stats_load_failed", error=str(exc))
    return defaults


def _save_stats(stats: dict) -> None:
    """Save stats to local JSON file."""
    try:
        with open(settings.stats_file, "w", encoding="utf-8") as f:
            json.dump(stats, f)
    except Exception as exc:
        logger.warning("stats_save_failed", error=str(exc))


def get_local_count() -> int:
    """Get local generation count."""
    return _load_stats().get("total_generations", 0)


async def get_supabase_stats() -> int | None:
    """Fetch total generation count from Supabase."""
    if not settings.supabase_url or not settings.supabase_key:
        return None
    try:
        headers = {
            "apikey": settings.supabase_key,
            "Authorization": f"Bearer {settings.supabase_key}",
        }
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{settings.supabase_url}/rest/v1/stats?id=eq.1",
                headers=headers,
                timeout=5.0,
            )
        if resp.status_code == 200:
            data = resp.json()
            if data:
                return int(data[0].get("total_generations", 0))
    except Exception as exc:
        logger.warning("supabase_stats_fetch_failed", error=str(exc))
    return None


async def increment_stats() -> None:
    """Increment generation count in both local file and Supabase."""
    with _stats_lock:
        stats = _load_stats()
        stats["total_generations"] = stats.get("total_generations", 0) + 1
        _save_stats(stats)
        logger.info("stats_incremented", total=stats["total_generations"])

    if settings.supabase_url and settings.supabase_key:
        try:
            headers = {
                "apikey": settings.supabase_key,
                "Authorization": f"Bearer {settings.supabase_key}",
                "Content-Type": "application/json",
                "Prefer": "return=minimal",
            }
            async with httpx.AsyncClient() as client:
                await client.post(
                    f"{settings.supabase_url}/rest/v1/rpc/increment_gen_count",
                    headers=headers,
                    timeout=5.0,
                )
        except Exception as exc:
            logger.warning("supabase_increment_failed", error=str(exc))
