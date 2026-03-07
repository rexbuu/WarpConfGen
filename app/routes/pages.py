"""Page routes for serving the HTML UI via Jinja2 templates."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.config import settings
from app.services.stats import get_local_count, get_supabase_stats

# Resolve template dir — works for both local dev and Vercel serverless
_file_based = Path(__file__).resolve().parent.parent.parent / "templates"
_cwd_based = Path.cwd() / "templates"
TEMPLATE_DIR = _file_based if _file_based.is_dir() else _cwd_based
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Serve the main WarpGen page."""
    supabase_count = await get_supabase_stats()
    local_count = get_local_count()
    display_count = supabase_count if supabase_count is not None else local_count

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "display_count": display_count,
            "mode": "auto",
            "selected_ip": "",
            "custom_ip": "",
            "port": 500,
            "known_ips": settings.known_warp_ips,
        },
    )
