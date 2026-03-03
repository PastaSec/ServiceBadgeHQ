from datetime import datetime, timezone
from urllib.parse import quote
import hashlib
import secrets
import html
import re
import os
import time
import csv
from io import StringIO
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException, Form, Request, File, UploadFile
from fastapi.responses import HTMLResponse, Response, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from sqlalchemy.orm import Session

from passlib.hash import bcrypt

from app.db import get_db
from app.utils import format_us_phone_display

app = FastAPI()

# Serve /static for PWA assets
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Cookies
TECH_SESSION_COOKIE = "sbhq_session"
ADMIN_SESSION_COOKIE = "sbhq_admin_session"
COMPANY_SESSION_COOKIE = "sbhq_company_session"

# In-memory rate limiting (per process).
_RATE_LIMIT_STATE = {}
_RATE_LIMIT_RULES = {
    "pair": (20, 300),      # 20 attempts / 5 min
    "rating": (90, 300),    # 90 requests / 5 min
    "feedback": (45, 300),  # 45 submissions / 5 min
}
_UPLOAD_MAX_IMAGE_BYTES = 5 * 1024 * 1024
_ALLOWED_IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".webp"}


def _client_ip(request: Request) -> str:
    xfwd = request.headers.get("x-forwarded-for", "")
    if xfwd:
        return xfwd.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _enforce_rate_limit(request: Request, bucket: str):
    limit, window = _RATE_LIMIT_RULES[bucket]
    now = time.time()
    key = f"{bucket}:{_client_ip(request)}"
    window_start = now - window

    stamps = _RATE_LIMIT_STATE.get(key, [])
    stamps = [s for s in stamps if s > window_start]
    if len(stamps) >= limit:
        raise HTTPException(status_code=429, detail="Too many requests. Please try again shortly.")

    stamps.append(now)
    _RATE_LIMIT_STATE[key] = stamps


def _save_uploaded_image(file: UploadFile | None, subdir: str, prefix: str) -> str | None:
    if not file or not (file.filename or "").strip():
        return None

    content_type = (file.content_type or "").lower()
    if not content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Upload must be an image")

    raw_ext = Path(file.filename).suffix.lower()
    ext = raw_ext if raw_ext in _ALLOWED_IMAGE_EXTS else ""
    if not ext:
        ext_by_type = {
            "image/jpeg": ".jpg",
            "image/png": ".png",
            "image/webp": ".webp",
        }
        ext = ext_by_type.get(content_type, "")
    if ext not in _ALLOWED_IMAGE_EXTS:
        raise HTTPException(status_code=400, detail="Allowed image formats: .jpg, .jpeg, .png, .webp")

    safe_subdir = re.sub(r"[^a-zA-Z0-9._-]+", "-", (subdir or "").strip()) or "misc"
    safe_prefix = re.sub(r"[^a-zA-Z0-9._-]+", "-", (prefix or "").strip()) or "image"

    out_dir = STATIC_DIR / "uploads" / safe_subdir
    out_dir.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    filename = f"{safe_prefix}-{stamp}-{secrets.token_hex(4)}{ext}"
    out_path = out_dir / filename

    blob = file.file.read(_UPLOAD_MAX_IMAGE_BYTES + 1)
    if len(blob) > _UPLOAD_MAX_IMAGE_BYTES:
        raise HTTPException(status_code=400, detail="Image too large (max 5 MB)")
    if not blob:
        raise HTTPException(status_code=400, detail="Uploaded image is empty")

    out_path.write_bytes(blob)
    return f"/static/uploads/{safe_subdir}/{filename}"


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' https: data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none';"
    )
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    return response


# -----------------------------
# Basic health
# -----------------------------
@app.get("/health")
def health():
    return {"ok": True}


# Optional: make curl -I happy (HEAD)
@app.head("/health")
def health_head():
    return Response(status_code=200)


@app.get("/.well-known/assetlinks.json")
def assetlinks():
    package_name = (os.getenv("TWA_PACKAGE_NAME") or "").strip()
    fingerprints_raw = (os.getenv("TWA_SHA256_CERT_FINGERPRINTS") or "").strip()

    if not package_name or not fingerprints_raw:
        return []

    fingerprints = [fp.strip() for fp in fingerprints_raw.split(",") if fp.strip()]
    if not fingerprints:
        return []

    return [
        {
            "relation": ["delegate_permission/common.handle_all_urls"],
            "target": {
                "namespace": "android_app",
                "package_name": package_name,
                "sha256_cert_fingerprints": fingerprints,
            },
        }
    ]


# -----------------------------
# PWA + Shared UI (site-wide)
# -----------------------------
def _pwa_head() -> str:
    return """
    <meta name="theme-color" content="#142030" />
    <link rel="manifest" href="/static/manifest.webmanifest" />
    <link rel="icon" href="/static/favicon.ico" sizes="any" />
    <link rel="shortcut icon" href="/static/favicon.ico" type="image/x-icon" />

    <!-- App icons -->
    <link rel="icon" type="image/png" sizes="192x192" href="/static/icon-192.png" />
    <link rel="icon" type="image/png" sizes="512x512" href="/static/icon-512.png" />

    <!-- iOS "Add to Home Screen" support -->
    <meta name="apple-mobile-web-app-capable" content="yes" />
    <meta name="apple-mobile-web-app-status-bar-style" content="default" />
    <meta name="apple-mobile-web-app-title" content="ServiceBadgeHQ" />
    <link rel="apple-touch-icon" href="/static/icon-192.png" />

    <script>
      if ('serviceWorker' in navigator) {
        window.addEventListener('load', () => {
          navigator.serviceWorker.register('/static/sw.js').catch(() => {});
        });
      }
    </script>
    """


def _ui_style() -> str:
    return """
    <style>
      :root{
        --bg:#142030;
        --card:#ffffff;

        --navy:#142030;
        --yellow:#efab16;

        --ink: var(--navy);
        --muted:#5a6472;

        --border:#e7ebf0;
        --soft:#f5f7fa;

        --radius:16px;
        --shadow: 0 10px 24px rgba(20,32,48,0.06);
      }

      *{ box-sizing:border-box; }
      body{
        background: var(--bg);
        color:var(--ink);
        font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
      }

      a{ color:inherit; }
      .wrap{ max-width:920px; margin:0 auto; }
      .page{ margin-top:16px; }

      .topbar{
        display:flex; align-items:center; justify-content:space-between;
        gap:16px; padding:16px 18px;
        border:1px solid var(--border);
        border-radius:20px;
        background:
          radial-gradient(560px 120px at 16% -24%, var(--yellow) 0%, transparent 62%),
          linear-gradient(180deg, rgba(255,255,255,0.98), rgba(247,250,255,0.98));
        box-shadow: 0 14px 30px rgba(20,32,48,0.12);
        position:relative;
        overflow:hidden;
        color:var(--ink);
      }
      @media (max-width: 760px){
        .topbar{
          flex-direction:column;
          align-items:flex-start;
        }
      }
      .topbar::after{
        content:"";
        position:absolute;
        left:0;
        right:0;
        bottom:0;
        height:4px;
        background:linear-gradient(90deg, var(--yellow) 0%, #ffcf62 25%, var(--navy) 100%);
      }
      @supports (background: color-mix(in srgb, #000 50%, #fff)){
        .topbar::after{
          background:linear-gradient(
            90deg,
            var(--yellow) 0%,
            color-mix(in srgb, var(--yellow) 55%, white) 25%,
            var(--navy) 100%
          );
        }
      }

      .brand{
        display:flex; align-items:center; gap:16px;
        font-weight:900; letter-spacing:0.02em;
      }
      .brand-badge{
        width:34px; height:34px; border-radius:10px;
        background:var(--navy); color:#fff;
        display:flex; align-items:center; justify-content:center;
        font-weight:900;
      }
      .brand-logo{
        width:120px;
        height:120px;
        border-radius:20px;
        border:1px solid var(--border);
        object-fit:cover;
        display:block;
        background:#fff;
        box-shadow: 0 10px 24px rgba(20,32,48,0.16);
      }
      @media (max-width: 520px){
        .brand-logo{
          width:92px;
          height:92px;
        }
      }
      .brand-name{
        font-size:34px;
        line-height:1;
        letter-spacing:0.01em;
        font-weight:950;
        color:#0e1724;
        text-transform:uppercase;
      }
      .brand-sub{
        margin-top:6px;
        font-size:14px;
        color:#2a3a4d;
        font-weight:700;
      }

      .kicker{
        font-size:12px; letter-spacing:0.10em;
        text-transform:uppercase; color:var(--muted);
      }
      .topbar-actions{
        display:flex;
        flex-wrap:wrap;
        gap:8px;
        justify-content:flex-end;
      }
      .topbar-actions .btn{
        width:auto;
        padding:9px 12px;
        border-radius:12px;
      }
      .site-footer{
        margin-top:18px;
        padding:14px 6px 6px 6px;
        text-align:center;
        font-size:13px;
        color:#ffffff;
      }
      .site-footer a{
        color:#ffffff;
        font-weight:700;
        text-decoration:none;
      }
      .site-footer a:hover{
        text-decoration:underline;
      }

      h1{ font-size:28px; line-height:1.15; margin:14px 0 6px 0; }
      h2{ font-size:16px; margin:18px 0 10px 0; }
      h1, h2{ color:#f3f7fd; }
      p{ line-height:1.55; margin:0 0 12px 0; }
      .muted{ color:var(--muted); }
      .card h1, .card h2,
      .hero h1, .hero h2,
      .media h1, .media h2,
      .topbar h1, .topbar h2{
        color:var(--ink);
      }
      @media (min-width: 720px){
        h1{ font-size:34px; }
      }

      .card{
        background:var(--card);
        border:1px solid var(--border);
        border-radius:var(--radius);
        padding:16px;
        box-shadow: var(--shadow);
        color:var(--ink);
      }
      .card + .card{ margin-top:12px; }

      .grid{ display:grid; gap:12px; }
      @media (min-width: 720px){
        .grid.two{ grid-template-columns: 1fr 1fr; }
      }

      .btn{
        display:block;
        width:100%;
        text-align:center;
        padding:12px 14px;
        border-radius:14px;
        border:1px solid var(--border);
        background:#fff;
        font-weight:900;
        text-decoration:none;
        cursor:pointer;
        transition: transform 0.12s ease, box-shadow 0.12s ease, border-color 0.12s ease;
      }
      .btn:hover{
        transform: translateY(-1px);
        box-shadow: 0 6px 14px rgba(20,32,48,0.08);
      }
      .btn-primary{
        background:var(--yellow);
        color:#111827;
        border-color:var(--yellow);
      }
      .btn-accent{
        background:var(--navy);
        color:#ffffff;
        border-color: var(--navy);
      }
      .btn-soft{ background:var(--soft); }
      .btn-link{ text-decoration:none; }

      .pill{
        display:inline-block;
        padding:6px 10px;
        border-radius:999px;
        border:1px solid rgba(239,171,22,0.35);
        background: rgba(239,171,22,0.14);
        font-size:12px;
        color: var(--navy);
        font-weight:800;
      }

      .hr{ height:1px; background:var(--border); margin:14px 0; }
      .row{ display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
      .hero{
        padding:26px;
        border-radius:22px;
        background: linear-gradient(165deg, #ffffff 0%, #fbfdff 42%, #f6f9fd 100%);
        border:1px solid var(--border);
        box-shadow: 0 14px 30px rgba(20,32,48,0.08);
        margin-top:16px;
        color:var(--ink);
      }
      .hero p{ max-width:68ch; }
      .hero-split{
        display:grid;
        gap:14px;
      }
      @media (min-width: 900px){
        .hero-split{
          grid-template-columns: 1.15fr 0.85fr;
          align-items:start;
        }
      }
      .hero-actions{
        display:flex;
        flex-wrap:wrap;
        gap:10px;
        margin-top:14px;
      }
      .hero-actions .btn{
        width:auto;
        min-width:150px;
      }
      .home-login-row{
        margin-top:10px;
        display:flex;
        gap:10px;
        flex-wrap:wrap;
      }
      .home-login-row .btn{
        width:auto;
        padding:9px 12px;
        border-radius:12px;
      }
      .home-right-links{
        margin-top:10px;
        display:flex;
        gap:8px;
        flex-wrap:wrap;
        justify-content:flex-end;
      }
      .home-right-links .btn{
        width:auto;
        padding:9px 12px;
        border-radius:12px;
      }
      .home-footer-links{
        margin-top:12px;
        display:flex;
        gap:8px;
        flex-wrap:wrap;
        justify-content:flex-end;
      }
      .home-footer-links .btn{
        width:auto;
        padding:8px 11px;
        border-radius:12px;
      }
      .step-grid{
        display:grid;
        gap:12px;
        margin-top:12px;
      }
      @media (min-width: 720px){
        .step-grid{
          grid-template-columns: 1fr 1fr 1fr;
        }
      }
      .step-num{
        width:30px;
        height:30px;
        border-radius:999px;
        display:inline-flex;
        align-items:center;
        justify-content:center;
        background:var(--navy);
        color:#fff;
        font-weight:900;
        margin-bottom:8px;
      }
      .trust-cues{
        display:flex;
        gap:10px;
        flex-wrap:wrap;
        margin-top:10px;
      }
      .media-grid{
        display:grid;
        gap:12px;
      }
      @media (min-width: 720px){
        .media-grid.two{
          grid-template-columns: 1fr 1fr;
        }
      }
      .media{
        border:1px dashed rgba(20,32,48,0.24);
        border:1px dashed color-mix(in srgb, var(--navy) 26%, white);
        border-radius:16px;
        padding:12px;
        background:
          linear-gradient(160deg, rgba(239,171,22,0.08), rgba(255,255,255,0.92)),
          linear-gradient(160deg, color-mix(in srgb, var(--yellow) 10%, white), rgba(255,255,255,0.92)),
          linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
        color:var(--ink);
      }
      .card .muted,
      .hero .muted,
      .media .muted,
      .topbar .muted{
        color:#5a6472;
      }
      .media-banner{
        min-height:220px;
      }
      .media-img{
        width:100%;
        display:block;
        border-radius:18px;
        box-shadow: 0 10px 24px rgba(20,32,48,0.10);
      }
      .media-slot{
        width:100%;
        overflow:hidden;
        border-radius:18px;
      }
      .media-slot.hero-shot{
        aspect-ratio: 16 / 10;
      }
      .media-slot.banner-shot{
        aspect-ratio: 16 / 9;
      }
      .media-slot.badge-shot{
        aspect-ratio: 16 / 10;
      }
      .media-slot > .media-img{
        width:100%;
        height:100%;
        object-fit:cover;
      }
      .media-ph{
        min-height:170px;
        border:1px dashed rgba(20,32,48,0.2);
        border-radius:12px;
        border:1px dashed color-mix(in srgb, var(--navy) 22%, white);
        background:
          radial-gradient(520px 160px at 0% 0%, rgba(239,171,22,0.18), transparent 60%),
          radial-gradient(520px 160px at 0% 0%, color-mix(in srgb, var(--yellow) 24%, white), transparent 60%),
          linear-gradient(180deg, #ffffff 0%, #f4f8fd 100%);
        display:flex;
        align-items:center;
        justify-content:center;
        text-align:center;
        padding:14px;
        color:var(--muted);
        font-weight:700;
      }
      .media-cap{
        margin-top:8px;
        font-size:12px;
        color:var(--muted);
      }
      .score-row{
        display:flex;
        gap:10px;
        flex-wrap:wrap;
      }
      .score-btn{
        width:auto !important;
        min-width:44px;
        padding:10px 12px !important;
      }
      .tech-profile{
        display:grid;
        gap:12px;
        margin-top:12px;
      }
      @media (min-width: 720px){
        .tech-profile{
          grid-template-columns: 280px 1fr;
          align-items:start;
        }
      }
      .tech-photo{
        width:100%;
        max-width:280px;
        border-radius:14px;
        border:1px solid var(--border);
        display:block;
      }
      .tech-bio{
        margin:0;
      }
      .pay-grid{
        display:grid;
        gap:10px;
        grid-template-columns: 1fr 1fr;
        margin-top:10px;
      }
      @media (min-width: 720px){
        .pay-grid{
          grid-template-columns: 1fr 1fr 1fr;
        }
      }
      .pay-item{
        display:flex;
        align-items:center;
        gap:8px;
        padding:10px 12px;
        border-radius:12px;
        border:1px solid var(--border);
        background:#fff;
        text-decoration:none;
        font-weight:800;
      }
      .pay-logo{
        width:22px;
        height:22px;
        border-radius:999px;
        display:inline-flex;
        align-items:center;
        justify-content:center;
        font-size:12px;
        font-weight:900;
        color:#fff;
      }
      .pay-item.active{
        border-color: color-mix(in srgb, var(--pay-color) 35%, white);
        background: color-mix(in srgb, var(--pay-color) 10%, white);
      }
      .pay-item.active .pay-logo{
        background: var(--pay-color);
      }
      .pay-item.inactive{
        opacity:0.45;
        cursor:not-allowed;
        background:#f7f8fa;
      }
      .pay-item.inactive .pay-logo{
        background:#7f8895;
      }
      input, select, textarea{
        width:100%;
        padding:10px;
        border:1px solid var(--border);
        border-radius:14px;
        background:#fff;
        color:var(--ink);
        font: inherit;
      }
      input:focus, select:focus, textarea:focus{
        outline:none;
        border-color: var(--yellow);
        box-shadow: 0 0 0 3px rgba(239,171,22,0.2);
      }
      table{
        width:100%;
        border-collapse: collapse;
        font-size:14px;
      }
      th{
        text-align:left;
        padding:10px;
        border-bottom:1px solid var(--border);
        background: var(--soft);
      }
      td{
        padding:10px;
        border-bottom:1px solid var(--border);
      }

      code{
        background:var(--soft);
        padding:2px 6px;
        border-radius:8px;
        border:1px solid var(--border);
        font-size:12px;
      }

      /* Bottom action bar */
      .bottom-bar{
        position:fixed; left:0; right:0; bottom:0;
        padding:10px;
        background:#fff;
        border-top:1px solid var(--border);
        z-index:9999;
      }
      .bottom-inner{
        max-width:820px; margin:0 auto;
        display:flex; gap:10px;
      }
      .bottom-inner a{
        flex:1;
        text-align:center;
        padding:10px;
        border:1px solid var(--border);
        border-radius:14px;
        text-decoration:none;
        background:#fff;
      }
      .bottom-title{ font-weight:900; color: var(--navy); }
      .bottom-sub{ font-size:12px; color:var(--muted); margin-top:2px; }
      .bottom-spacer{ height:98px; }
    </style>
    """


def _brand_header(
    right_html: str = "",
    brand_name: str = "ServiceBadgeHQ",
    brand_subtitle: str = "Verified Service Professional identity at the door.",
    logo_url: str = "/static/logo.png",
) -> str:
    return f"""
    <div class="topbar">
      <div>
        <div class="brand">
          <img class="brand-logo" src="{html.escape(logo_url, quote=True)}" alt="{html.escape(brand_name)} logo" />
          <div>
            <div class="brand-name">{html.escape(brand_name)}</div>
            <div class="brand-sub">{html.escape(brand_subtitle)}</div>
            <div class="kicker">Proof at the door.</div>
          </div>
        </div>
      </div>
      <div class="topbar-actions">{right_html}</div>
    </div>
    """


def _html_page(
    title: str,
    body: str,
    right_html: str = "",
    brand_name: str = "ServiceBadgeHQ",
    brand_subtitle: str = "Verified Service Professional identity at the door.",
    logo_url: str = "/static/logo.png",
    primary_color: str = "",
    accent_color: str = "",
) -> str:
    brand_overrides = ""
    has_company_theme = False
    if re.match(r"^#[0-9a-fA-F]{3}([0-9a-fA-F]{3})?$", primary_color or ""):
        brand_overrides += f"--navy:{primary_color};"
        has_company_theme = True
    if re.match(r"^#[0-9a-fA-F]{3}([0-9a-fA-F]{3})?$", accent_color or ""):
        brand_overrides += f"--yellow:{accent_color};"
        has_company_theme = True
    if has_company_theme:
        brand_overrides += (
            "--ink:var(--navy);"
            "--muted:color-mix(in srgb, var(--navy) 58%, white);"
            "--border:color-mix(in srgb, var(--navy) 14%, white);"
            "--soft:color-mix(in srgb, var(--navy) 7%, white);"
            "--shadow:0 10px 24px color-mix(in srgb, var(--navy) 14%, transparent);"
        )

    brand_override_style = f"<style>:root{{{brand_overrides}}}</style>" if brand_overrides else ""
    return f"""
    <html>
      <head>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>{title}</title>
        {_pwa_head()}
        {_ui_style()}
        {brand_override_style}
      </head>
      <body style="margin:0; padding:18px;">
        <div class="wrap">
          {_brand_header(right_html, brand_name=brand_name, brand_subtitle=brand_subtitle, logo_url=logo_url)}
          <main class="page">{body}</main>
          <footer class="site-footer">Copyright <a href="https://www.tagline-branding.com" target="_blank" rel="noopener noreferrer">Tagline Branding, LLC.</a> 2026</footer>
        </div>
      </body>
    </html>
    """


# -----------------------------
# Helpers: hashing / tokens
# -----------------------------
def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _set_cookie(resp: Response, key: str, token: str):
    resp.set_cookie(
        key=key,
        value=token,
        httponly=True,
        samesite="lax",
        secure=True,
        max_age=60 * 60 * 24 * 30,  # 30 days
    )


def _clear_cookie(resp: Response, key: str):
    resp.delete_cookie(key)


# Cache DB column-existence checks for this process.
_COLUMN_EXISTS_CACHE = {}


def _has_column(db: Session, table_name: str, column_name: str) -> bool:
    key = (table_name, column_name)
    if key in _COLUMN_EXISTS_CACHE:
        return _COLUMN_EXISTS_CACHE[key]

    exists = db.execute(
        text(
            """
            SELECT EXISTS (
                SELECT 1
                FROM information_schema.columns
                WHERE table_name = :table_name
                  AND column_name = :column_name
            )
            """
        ),
        {"table_name": table_name, "column_name": column_name},
    ).scalar_one()
    _COLUMN_EXISTS_CACHE[key] = bool(exists)
    return _COLUMN_EXISTS_CACHE[key]


def _tech_optional_profile_columns():
    return [
        "photo_url",
        "bio_short",
        "venmo_url",
        "zelle_url",
        "paypal_url",
        "cashapp_url",
        "apple_pay_url",
        "google_pay_url",
    ]


def _missing_optional_tech_columns(db: Session):
    missing = []
    for col in _tech_optional_profile_columns():
        if not _has_column(db, "techs", col):
            missing.append(col)
    return missing


def _company_branding_columns():
    return ["brand_logo_url", "brand_primary_color", "brand_accent_color", "brand_tagline"]


def _ensure_company_auth_tables(db: Session):
    db.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS company_users (
              id BIGSERIAL PRIMARY KEY,
              company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
              email TEXT NOT NULL UNIQUE,
              password_hash TEXT NOT NULL,
              role TEXT NOT NULL DEFAULT 'owner',
              is_active BOOLEAN NOT NULL DEFAULT TRUE,
              created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
    )
    db.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS company_sessions (
              id BIGSERIAL PRIMARY KEY,
              company_user_id BIGINT NOT NULL REFERENCES company_users(id) ON DELETE CASCADE,
              token_hash TEXT NOT NULL UNIQUE,
              user_agent TEXT,
              ip TEXT,
              created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
              last_seen_at TIMESTAMPTZ,
              revoked_at TIMESTAMPTZ
            )
            """
        )
    )
    db.commit()


# -----------------------------
# Helpers: Company / Tech fetch
# -----------------------------
def _get_company(db: Session, company_code: str):
    optional_columns = _company_branding_columns()
    select_parts = [
        "id",
        "name",
        "code",
        "phone_e164",
        "email",
        "website",
        "address_line1",
        "address_line2",
        "city",
        "state",
        "zip",
        "google_review_url",
        "review_mode_hours",
    ]
    for col in optional_columns:
        if _has_column(db, "companies", col):
            select_parts.append(col)
        else:
            select_parts.append(f"NULL AS {col}")

    return db.execute(
        text(f"SELECT {', '.join(select_parts)} FROM companies WHERE code = :code"),
        {"code": company_code.upper()},
    ).mappings().first()


def _get_tech(db: Session, company_id, tech_slug: str):
    optional_columns = _tech_optional_profile_columns()

    select_parts = ["id", "name", "role", "slug", "license_number", "status", "review_mode_until", "pin_hash"]
    for col in optional_columns:
        if _has_column(db, "techs", col):
            select_parts.append(col)
        else:
            select_parts.append(f"NULL AS {col}")

    sql = f"""
        SELECT {", ".join(select_parts)}
        FROM techs
        WHERE company_id = :company_id AND slug = :slug
    """

    return db.execute(text(sql), {"company_id": company_id, "slug": tech_slug.lower()}).mappings().first()


def _company_branding_kwargs(company: dict) -> dict:
    if not company:
        return {}
    return {
        "brand_name": company.get("name") or "ServiceBadgeHQ",
        "brand_subtitle": company.get("brand_tagline") or "Verified Service Professional identity at the door.",
        "logo_url": company.get("brand_logo_url") or "/static/logo.png",
        "primary_color": company.get("brand_primary_color") or "",
        "accent_color": company.get("brand_accent_color") or "",
    }


# -----------------------------
# Admin auth: current admin
# -----------------------------
def get_current_admin(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get(ADMIN_SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="Not logged in")

    token_hash = _hash_token(token)

    sess = db.execute(
        text(
            """
            SELECT s.admin_id
            FROM admin_sessions s
            WHERE s.token_hash = :th
              AND s.revoked_at IS NULL
            """
        ),
        {"th": token_hash},
    ).mappings().first()

    if not sess:
        raise HTTPException(status_code=401, detail="Session invalid or revoked")

    admin = db.execute(
        text("SELECT id, email, is_active FROM admin_users WHERE id=:id"),
        {"id": sess["admin_id"]},
    ).mappings().first()

    if not admin or not admin["is_active"]:
        raise HTTPException(status_code=403, detail="Admin disabled")

    db.execute(
        text("UPDATE admin_sessions SET last_seen_at = now() WHERE token_hash = :th"),
        {"th": token_hash},
    )
    db.commit()

    return admin


def get_current_company_user(request: Request, db: Session = Depends(get_db)):
    _ensure_company_auth_tables(db)
    token = request.cookies.get(COMPANY_SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="Not logged in")

    token_hash = _hash_token(token)
    sess = db.execute(
        text(
            """
            SELECT cs.company_user_id
            FROM company_sessions cs
            WHERE cs.token_hash = :th
              AND cs.revoked_at IS NULL
            """
        ),
        {"th": token_hash},
    ).mappings().first()
    if not sess:
        raise HTTPException(status_code=401, detail="Session invalid or revoked")

    cu = db.execute(
        text(
            """
            SELECT cu.id, cu.company_id, cu.email, cu.role, cu.is_active,
                   c.name AS company_name, c.code AS company_code
            FROM company_users cu
            JOIN companies c ON c.id = cu.company_id
            WHERE cu.id = :id
            """
        ),
        {"id": sess["company_user_id"]},
    ).mappings().first()

    if not cu or not cu["is_active"]:
        raise HTTPException(status_code=403, detail="Company user disabled")

    db.execute(
        text("UPDATE company_sessions SET last_seen_at = now() WHERE token_hash = :th"),
        {"th": token_hash},
    )
    db.commit()
    return cu


# -----------------------------
# Tech auth: current tech
# -----------------------------
def get_current_tech(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get(TECH_SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="Not logged in")

    token_hash = _hash_token(token)

    sess = db.execute(
        text(
            """
            SELECT ds.tech_id
            FROM device_sessions ds
            WHERE ds.token_hash = :th
              AND ds.revoked_at IS NULL
            """
        ),
        {"th": token_hash},
    ).mappings().first()

    if not sess:
        raise HTTPException(status_code=401, detail="Session invalid or revoked")

    tech = db.execute(
        text(
            """
            SELECT t.id, t.company_id, t.name, t.role, t.slug, t.status
            FROM techs t
            WHERE t.id = :tid
            """
        ),
        {"tid": sess["tech_id"]},
    ).mappings().first()

    if not tech:
        raise HTTPException(status_code=401, detail="Service Pro not found")

    if tech["status"] != "active":
        raise HTTPException(status_code=403, detail="Service Pro disabled")

    db.execute(
        text("UPDATE device_sessions SET last_seen_at = now() WHERE token_hash = :th"),
        {"th": token_hash},
    )
    db.commit()

    return tech


# -----------------------------
# Public landing page (new)
# -----------------------------
@app.get("/", response_class=HTMLResponse)
def home():
    right = """
      <a class="btn btn-soft" href="/company/login">Company Login</a>
      <a class="btn btn-soft" href="/login">Service Pro Login</a>
      <a class="btn btn-soft" href="/admin/login">Admin Login</a>
    """
    body = """
    <section class="hero">
      <div class="hero-split">
        <div>
          <div class="pill">Proof at the door.</div>
          <h1>Show up trusted before a word is said.</h1>
          <p class="muted">
            Verify who is at the door in seconds. Keep office contact front and center.
            Route strong jobs to Google reviews and unhappy jobs to a private office inbox.
          </p>
          <div class="hero-actions">
            <a class="btn btn-primary" href="/company/signup">Company Sign Up</a>
            <a class="btn btn-soft" href="https://servicebadgehq.com/t/SBHQ1/mike">View Demo</a>
          </div>
          <div class="trust-cues">
            <span class="pill">No customer install</span>
            <span class="pill">Office-only contact</span>
            <span class="pill">QR + NFC ready</span>
          </div>
        </div>
        <div class="media">
          <div class="pill">Badge close-up</div>
          <div class="media-slot hero-shot" style="margin-top:10px;">
            <img class="media-img" src="/static/marketing-badge-closeup.jpg" alt="Service badge close-up">
          </div>
          <div class="media-cap">Uniform + badge detail that reinforces trust at the door.</div>
        </div>
      </div>
    </section>

    <div class="card" style="margin-top:14px;">
      <div class="pill">In-the-field visuals</div>
      <div class="media media-banner" style="margin-top:10px;">
        <div class="media-grid two">
          <div class="media-slot banner-shot">
            <img class="media-img" src="/static/marketing-tech-door.jpg" alt="Technician at a residential door with service badge visible">
          </div>
          <div class="media-slot banner-shot">
            <img class="media-img" src="/static/marketing-van.jpg" alt="Service van and uniformed technician lifestyle scene">
          </div>
        </div>
        <div class="media-cap">Real-world service moments your customers instantly recognize.</div>
      </div>
    </div>

    <div class="card" style="margin-top:14px;">
      <div class="pill">How it works</div>
      <div class="step-grid">
        <div class="card" style="margin:0; box-shadow:none;">
          <div class="step-num">1</div>
          <h2 style="margin:0 0 8px 0;">Tap or scan to verify</h2>
          <p class="muted" style="margin:0;">
            Customer opens your badge link instantly. They see who is on-site, your company, and office-only contact.
          </p>
        </div>
        <div class="card" style="margin:0; box-shadow:none;">
          <div class="step-num">2</div>
          <h2 style="margin:0 0 8px 0;">Service Pro flips Review Mode</h2>
          <p class="muted" style="margin:0;">
            After the job, your team member marks the visit complete and review mode turns on automatically.
          </p>
        </div>
        <div class="card" style="margin:0; box-shadow:none;">
          <div class="step-num">3</div>
          <h2 style="margin:0 0 8px 0;">Smart review routing</h2>
          <p class="muted" style="margin:0;">
            4–5 stars go to Google. 1–3 stays private so the office can fix it fast.
          </p>
        </div>
      </div>
    </div>

    <div class="media-grid two" style="margin-top:12px;">
      <div class="card">
        <div class="pill">Office inbox</div>
        <div class="media" style="margin-top:10px;">
          <div class="media-slot badge-shot">
            <img class="media-img" style="object-fit:contain; background:#f4f7fb;" src="/static/AdminFeedback.jpg" alt="Admin feedback inbox">
          </div>
          <div class="media-cap">Private feedback lands in one place so the office can fix issues quickly.</div>
        </div>
      </div>
      <div class="card">
        <div class="pill">Badge mockup</div>
        <div class="media" style="margin-top:10px;">
          <div class="media-slot badge-shot">
            <img class="media-img" src="/static/marketing-badge-closeup.jpg" alt="Badge mockup for QR and NFC ID design">
          </div>
          <div class="media-cap">Badge mockup for print-ready door trust assets.</div>
        </div>
      </div>
    </div>

    <div class="grid two" style="margin-top:12px;">
      <div class="card">
        <div class="pill">Built for trades</div>
        <h2 style="margin-top:10px;">Clean branding builds real trust.</h2>
        <p class="muted">
          HVAC, plumbing, pest, lawn, roofing, cleaning, pressure washing and more.
          Showing up in a t-shirt and hoping for trust isn’t a strategy.
        </p>
      </div>

      <div class="card">
        <div class="pill">What customers see</div>
        <h2 style="margin-top:10px;">Fast and frictionless</h2>
        <p class="muted">
          Verification links look like <code>/t/COMPANY/TECH</code>.
          No app download required. Personal Service Pro contact never shown by default.
        </p>
      </div>
    </div>

    <div class="home-footer-links">
      <a class="btn btn-soft" href="/company/login">Company Login</a>
      <a class="btn btn-soft" href="/login">Service Pro Login</a>
      <a class="btn btn-soft" href="/admin/login">Admin Login</a>
    </div>
    """
    return _html_page("ServiceBadgeHQ", body, right_html=right)


# -----------------------------
# vCard: Office contact only
# -----------------------------
@app.get("/c/{company_code}/office.vcf")
def office_vcard(company_code: str, db: Session = Depends(get_db)):
    company = db.execute(
        text(
            """
            SELECT name, phone_e164, email, website,
                   address_line1, address_line2, city, state, zip
            FROM companies
            WHERE code = :code
            """
        ),
        {"code": company_code.upper()},
    ).mappings().first()

    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

    vcf_lines = [
        "BEGIN:VCARD",
        "VERSION:3.0",
        f"N:{company['name']} Office;;;;",
        f"FN:{company['name']} Office",
        f"TEL;TYPE=WORK,VOICE:{company['phone_e164']}",
    ]

    if company.get("email"):
        vcf_lines.append(f"EMAIL;TYPE=WORK:{company['email']}")

    if company.get("website"):
        vcf_lines.append(f"URL:{company['website']}")

    if company.get("address_line1") or company.get("city") or company.get("state") or company.get("zip"):
        street_parts = []
        if company.get("address_line1"):
            street_parts.append(company["address_line1"])
        if company.get("address_line2"):
            street_parts.append(company["address_line2"])
        street = " ".join(street_parts)

        city = company.get("city") or ""
        state = company.get("state") or ""
        zipc = company.get("zip") or ""
        vcf_lines.append(f"ADR;TYPE=WORK:;;{street};{city};{state};{zipc};")

    vcf_lines.append("NOTE:Scheduling, service questions, and support.")
    vcf_lines.append("END:VCARD")

    vcf = "\r\n".join(vcf_lines) + "\r\n"
    filename = f"{company_code.upper()}-office.vcf"

    return Response(
        content=vcf,
        media_type="text/vcard",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# -----------------------------
# Bottom action bar (office-only)
# -----------------------------
def _contact_bar_html(company_code: str, phone_e164: str, phone_display: str, sms_body: str) -> str:
    sms_link = f"sms:{phone_e164}?body={quote(sms_body)}"
    tel_link = f"tel:{phone_e164}"
    vcard_link = f"/c/{company_code.upper()}/office.vcf"

    return f"""
    <div class="bottom-bar">
      <div class="bottom-inner">
        <a href="{sms_link}">
          <div class="bottom-title">Text Office</div>
          <div class="bottom-sub">{phone_display}</div>
        </a>
        <a href="{tel_link}">
          <div class="bottom-title">Call Office</div>
          <div class="bottom-sub">{phone_display}</div>
        </a>
        <a href="{vcard_link}">
          <div class="bottom-title">Save</div>
          <div class="bottom-sub">Add contact</div>
        </a>
      </div>
    </div>
    <div class="bottom-spacer"></div>
    """


def _verification_signal_html() -> str:
    stamp = datetime.now(timezone.utc).strftime("%b %d, %Y %H:%M UTC")
    return f"""
    <div class="card" style="margin-top:12px;">
      <div class="pill">Verified Service Pro</div>
      <p class="muted" style="margin-top:10px;">
        Last verified: <b>{stamp}</b>. For safety, communication on this page is routed to the office.
      </p>
    </div>
    """


def _safe_href(url: str) -> str:
    v = (url or "").strip()
    if not v:
        return ""
    if re.match(r"^(https://|http://|mailto:|tel:|sms:)", v, flags=re.IGNORECASE):
        return v
    return ""


def _normalize_payment_link(kind: str, raw_value: str) -> str:
    value = (raw_value or "").strip()
    if not value:
        return ""

    direct = _safe_href(value)
    if direct:
        return direct

    if kind == "venmo":
        handle = value.lstrip("@")
        return f"https://venmo.com/{quote(handle)}" if handle else ""
    if kind == "paypal":
        handle = value.split("/")[-1].strip()
        return f"https://paypal.me/{quote(handle)}" if handle else ""
    if kind == "cashapp":
        handle = value.lstrip("$")
        return f"https://cash.app/${quote(handle)}" if handle else ""
    if kind == "zelle":
        if "@" in value:
            return f"mailto:{quote(value)}"
        digits = re.sub(r"\D", "", value)
        if len(digits) >= 10:
            return f"sms:+1{digits[-10:]}"
    return ""


def _tech_profile_html(tech) -> str:
    photo = (tech.get("photo_url") or "").strip()
    has_photo = bool(_safe_href(photo))
    photo_src = html.escape(photo, quote=True) if has_photo else "/static/tech-placeholder.svg"
    photo_note = "" if has_photo else "<div class='muted' style='font-size:12px; margin-top:6px;'>Photo coming soon</div>"

    bio = (tech.get("bio_short") or "").strip()
    demo_bio = (
        "Friendly, background-checked service professional focused on clean work, "
        "clear communication, and respect for your home."
    )
    bio_text = html.escape(bio if bio else demo_bio)
    bio_badge = "" if bio else "<div class='pill' style='margin-bottom:8px;'>Demo bio</div>"

    photo_html = f"""
    <div class="tech-profile">
      <div>
        <img src="{photo_src}" alt="{html.escape(tech['name'])}" class="tech-photo" />
        {photo_note}
      </div>
      <div>
        {bio_badge}
        <p class="muted tech-bio">{bio_text}</p>
      </div>
    </div>
    """

    payment_items = [
        ("venmo", "Venmo", tech.get("venmo_url")),
        ("zelle", "Zelle", tech.get("zelle_url")),
        ("paypal", "PayPal", tech.get("paypal_url")),
        ("cashapp", "Cash App", tech.get("cashapp_url")),
        ("applepay", "Apple Pay", tech.get("apple_pay_url")),
        ("googlepay", "Google Pay", tech.get("google_pay_url")),
    ]
    payment_styles = {
        "venmo": ("V", "#008cff"),
        "zelle": ("Z", "#6d1ed4"),
        "paypal": ("P", "#003087"),
        "cashapp": ("$", "#00d64f"),
        "applepay": ("A", "#111111"),
        "googlepay": ("G", "#4285f4"),
    }

    links = []
    for key, label, raw in payment_items:
        href = _normalize_payment_link(key, raw or "")
        mark, color = payment_styles[key]
        if href:
            links.append(
                f'<a class="pay-item active" style="--pay-color:{color};" rel="noopener noreferrer" target="_blank" '
                f'href="{html.escape(href, quote=True)}"><span class="pay-logo">{mark}</span><span>{label}</span></a>'
            )
        else:
            links.append(
                f'<div class="pay-item inactive" style="--pay-color:{color};" aria-disabled="true">'
                f'<span class="pay-logo">{mark}</span><span>{label}</span></div>'
            )

    payments_html = f"""
    <div style="margin-top:12px;">
      <div class="pill">Tip Links</div>
      <div class="pay-grid">{"".join(links)}</div>
    </div>
    """

    return photo_html + payments_html


# -----------------------------
# PUBLIC: Meet/Review pages
# -----------------------------
@app.get("/t/{company_code}/{tech_slug}", response_class=HTMLResponse)
def public_tech_page(company_code: str, tech_slug: str, db: Session = Depends(get_db)):
    company = _get_company(db, company_code)
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

    phone_e164 = company["phone_e164"]
    phone_display = format_us_phone_display(phone_e164)

    tech = _get_tech(db, company["id"], tech_slug)
    if not tech:
        raise HTTPException(status_code=404, detail="Service Pro not found")

    if tech["status"] != "active":
        sms_body = "Hi — I’m trying to verify a Service Professional at my door. Can you confirm who’s assigned today?"
        contact_bar = _contact_bar_html(company_code, phone_e164, phone_display, sms_body)

        body = f"""
        <h1>Verify your appointment</h1>
        <p class="muted">
          For your safety, this verification link isn’t currently active.
          Please contact <b>{company['name']}</b> to confirm your scheduled service.
        </p>

        <div class="card">
          <div class="pill">Office contact</div>
          <h2 style="margin-top:10px;">{phone_display}</h2>
          <p class="muted">Use the buttons below to text or call the office.</p>
        </div>

        {contact_bar}
        """
        return _html_page("Verify your appointment", body, **_company_branding_kwargs(company))

    now = datetime.now(timezone.utc)
    in_review_mode = False
    if tech["review_mode_until"] is not None:
        in_review_mode = tech["review_mode_until"] > now

    sms_body = (
        "Hi — quick question about my recent service. Can someone help me?"
        if in_review_mode
        else "Hi — I’m checking my appointment. Can you confirm today’s service details?"
    )
    contact_bar = _contact_bar_html(company_code, phone_e164, phone_display, sms_body)
    trust_signal = _verification_signal_html()

    lic_line = f"<div class='pill' style='margin-top:10px;'>Lic # {tech['license_number']}</div>" if tech["license_number"] else ""
    profile_extras = _tech_profile_html(tech)

    if not in_review_mode:
        body = f"""
        <h1>Meet your Service Professional.</h1>
        <p class="muted">Quick verification and office contact — that’s it.</p>

        <div class="card">
          <div class="pill">{company['name']}</div>
          <h2 style="margin-top:10px; font-size:22px;">{tech['name']}</h2>
          <div class="muted">{tech['role']}</div>
          {lic_line}
          {profile_extras}
          <div class="hr"></div>
          <p class="muted" style="margin:0;">
            If anything feels off, use the office contact buttons below.
          </p>
        </div>

        <div class="card">
          <div class="pill">Reviews open after service</div>
          <p class="muted" style="margin-top:10px;">
            Ratings appear here after the visit is marked complete by the office or Service Pro.
          </p>
        </div>

        {trust_signal}

        {contact_bar}
        """
        return _html_page(f"{tech['name']} — {company['name']}", body, **_company_branding_kwargs(company))

    cc = company_code.upper()
    slug = tech["slug"]

    body = f"""
    <h1>Thanks for choosing {company['name']}.</h1>
    <p class="muted">
      If we earned it, a quick review helps a lot. It helps the next customer feel confident calling us.
    </p>

    <div class="card">
      <div class="pill">{company['name']}</div>
      <h2 style="margin-top:10px; font-size:22px;">{tech['name']}</h2>
      <div class="muted">{tech['role']}</div>
      {lic_line}
      {profile_extras}
    </div>

    {trust_signal}

    <div class="card">
      <div class="pill">Rate your experience</div>
      <div class="score-row" style="margin-top:10px;">
        <a class="btn btn-soft score-btn" href="/t/{cc}/{slug}/rate?score=1">1</a>
        <a class="btn btn-soft score-btn" href="/t/{cc}/{slug}/rate?score=2">2</a>
        <a class="btn btn-soft score-btn" href="/t/{cc}/{slug}/rate?score=3">3</a>
        <a class="btn btn-soft score-btn" href="/t/{cc}/{slug}/rate?score=4">4</a>
        <a class="btn btn-soft score-btn" href="/t/{cc}/{slug}/rate?score=5">5</a>
      </div>
      <p class="muted" style="margin-top:10px;">
        4–5 stars will take you to Google. 1–3 stays private so we can fix it.
      </p>
    </div>

    {contact_bar}
    """
    return _html_page(f"Review — {company['name']}", body, **_company_branding_kwargs(company))


# -----------------------------
# PUBLIC: Rating + Feedback
# -----------------------------
@app.get("/t/{company_code}/{tech_slug}/rate", response_class=HTMLResponse)
def rate_experience(
    company_code: str,
    tech_slug: str,
    score: int,
    request: Request,
    db: Session = Depends(get_db),
):
    _enforce_rate_limit(request, "rating")
    if score < 1 or score > 5:
        raise HTTPException(status_code=400, detail="Score must be 1-5")

    company = db.execute(
        text("SELECT id, name, code, google_review_url, phone_e164 FROM companies WHERE code=:code"),
        {"code": company_code.upper()},
    ).mappings().first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    company_brand = _get_company(db, company_code) or company

    tech = db.execute(
        text("SELECT id, status, slug FROM techs WHERE company_id=:cid AND slug=:slug"),
        {"cid": company["id"], "slug": tech_slug.lower()},
    ).mappings().first()
    if not tech:
        raise HTTPException(status_code=404, detail="Service Pro not found")

    if tech["status"] != "active":
        raise HTTPException(status_code=400, detail="Service Professional not active")

    rating_id = db.execute(
        text(
            """
            INSERT INTO ratings (company_id, tech_id, score)
            VALUES (:company_id, :tech_id, :score)
            RETURNING id
            """
        ),
        {"company_id": company["id"], "tech_id": tech["id"], "score": score},
    ).scalar_one()
    db.commit()

    if score >= 4:
        return RedirectResponse(url=company["google_review_url"], status_code=302)

    phone_e164 = company["phone_e164"]
    phone_display = format_us_phone_display(phone_e164)
    sms_body = "Hi — quick question about my recent service. Can someone help me?"
    contact_bar = _contact_bar_html(company_code, phone_e164, phone_display, sms_body)

    cc = company_code.upper()
    slug = tech["slug"]

    body = f"""
    <h1>Thanks — we hear you.</h1>
    <p class="muted">
      We’d rather fix it than fight about it. Tell us what happened and the office will follow up.
    </p>

    <div class="card">
      <form method="post" action="/t/{cc}/{slug}/feedback">
        <input type="hidden" name="score" value="{score}" />
        <input type="hidden" name="rating_id" value="{rating_id}" />

        <label style="display:block; font-weight:900; margin-bottom:8px;">What went wrong?</label>
        <textarea name="message" rows="5" required style="font-family:inherit;"></textarea>

        <button class="btn btn-primary" type="submit" style="margin-top:12px;">
          Send privately to the office
        </button>

        <p class="muted" style="margin-top:10px;">
          This stays private — it does not post publicly.
        </p>
      </form>
    </div>

    {contact_bar}
    """
    return _html_page("We hear you", body, **_company_branding_kwargs(company_brand))


@app.post("/t/{company_code}/{tech_slug}/feedback", response_class=HTMLResponse)
def submit_feedback(
    company_code: str,
    tech_slug: str,
    request: Request,
    score: int = Form(...),
    message: str = Form(...),
    rating_id: str = Form(None),
    db: Session = Depends(get_db),
):
    _enforce_rate_limit(request, "feedback")
    message = (message or "").strip()
    if not message:
        raise HTTPException(status_code=400, detail="Message required")

    company = db.execute(
        text("SELECT id, name, phone_e164 FROM companies WHERE code=:code"),
        {"code": company_code.upper()},
    ).mappings().first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    company_brand = _get_company(db, company_code) or company

    tech = db.execute(
        text("SELECT id, status FROM techs WHERE company_id=:cid AND slug=:slug"),
        {"cid": company["id"], "slug": tech_slug.lower()},
    ).mappings().first()
    if not tech:
        raise HTTPException(status_code=404, detail="Service Pro not found")

    score_int = int(score)
    if score_int < 1 or score_int > 5:
        raise HTTPException(status_code=400, detail="Score must be 1-5")

    if not rating_id:
        rating_id = db.execute(
            text(
                """
                INSERT INTO ratings (company_id, tech_id, score)
                VALUES (:company_id, :tech_id, :score)
                RETURNING id
                """
            ),
            {"company_id": company["id"], "tech_id": tech["id"], "score": score_int},
        ).scalar_one()

    db.execute(
        text(
            """
            INSERT INTO feedback (rating_id, company_id, tech_id, message, status)
            VALUES (:rating_id, :company_id, :tech_id, :message, 'open')
            """
        ),
        {"rating_id": rating_id, "company_id": company["id"], "tech_id": tech["id"], "message": message},
    )
    db.commit()

    phone_e164 = company["phone_e164"]
    phone_display = format_us_phone_display(phone_e164)
    sms_body = "Hi — quick question about my recent service. Can someone help me?"
    contact_bar = _contact_bar_html(company_code, phone_e164, phone_display, sms_body)

    body = f"""
    <h1>Got it.</h1>
    <p class="muted">
      Thanks for letting us know. The office will follow up to make it right.
    </p>
    {contact_bar}
    """
    return _html_page("Received", body, **_company_branding_kwargs(company_brand))


# -----------------------------
# COMPANY PORTAL: signup + login + dashboard + settings
# -----------------------------
@app.get("/company/signup", response_class=HTMLResponse)
def company_signup_page():
    body = """
    <h1>Company Sign Up</h1>
    <p class="muted">Create your company account to manage branding and Service Pros.</p>
    <div class="card">
      <form method="post" action="/company/signup">
        <div class="grid two">
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Company name</label>
            <input name="name" required />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Company code</label>
            <input name="code" required maxlength="20" placeholder="ACME1" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Office phone (E.164)</label>
            <input name="phone_e164" required placeholder="+15551234567" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Google review URL</label>
            <input name="google_review_url" required placeholder="https://..." />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Your email</label>
            <input type="email" name="email" required />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Password</label>
            <input type="password" name="password" required />
          </div>
        </div>
        <button class="btn btn-primary" type="submit" style="margin-top:12px;">Create Company Account</button>
      </form>
      <p class="muted" style="margin-top:10px;">Already have an account? <a class="btn-link" href="/company/login">Log in</a></p>
    </div>
    """
    return _html_page("Company Sign Up", body)


@app.post("/company/signup")
def company_signup(
    request: Request,
    name: str = Form(...),
    code: str = Form(...),
    phone_e164: str = Form(...),
    google_review_url: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    _ensure_company_auth_tables(db)
    code_norm = (code or "").strip().upper()
    if not re.match(r"^[A-Z0-9_-]{3,20}$", code_norm):
        raise HTTPException(status_code=400, detail="Invalid company code format")
    if not (phone_e164 or "").strip().startswith("+"):
        raise HTTPException(status_code=400, detail="Phone must be E.164")
    if len((password or "").strip()) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    company_id = db.execute(
        text(
            """
            INSERT INTO companies (name, code, phone_e164, google_review_url, review_mode_hours)
            VALUES (:name, :code, :phone_e164, :google_review_url, 24)
            RETURNING id
            """
        ),
        {
            "name": (name or "").strip(),
            "code": code_norm,
            "phone_e164": (phone_e164 or "").strip(),
            "google_review_url": (google_review_url or "").strip(),
        },
    ).scalar_one()

    company_user_id = db.execute(
        text(
            """
            INSERT INTO company_users (company_id, email, password_hash, role, is_active)
            VALUES (:company_id, :email, :password_hash, 'owner', TRUE)
            RETURNING id
            """
        ),
        {
            "company_id": company_id,
            "email": (email or "").strip().lower(),
            "password_hash": bcrypt.hash((password or "").strip()),
        },
    ).scalar_one()
    db.commit()

    token = secrets.token_urlsafe(32)
    token_hash = _hash_token(token)
    db.execute(
        text(
            """
            INSERT INTO company_sessions (company_user_id, token_hash, user_agent, ip)
            VALUES (:company_user_id, :token_hash, :ua, :ip)
            """
        ),
        {
            "company_user_id": company_user_id,
            "token_hash": token_hash,
            "ua": request.headers.get("user-agent"),
            "ip": request.client.host if request.client else None,
        },
    )
    db.commit()

    resp = RedirectResponse(url="/company", status_code=302)
    _set_cookie(resp, COMPANY_SESSION_COOKIE, token)
    return resp


@app.get("/company/login", response_class=HTMLResponse)
def company_login_page():
    body = """
    <h1>Company Login</h1>
    <p class="muted">Access your company dashboard and branding controls.</p>
    <div class="card">
      <form method="post" action="/company/login">
        <label style="display:block; font-weight:900; margin-bottom:6px;">Email</label>
        <input type="email" name="email" required />
        <label style="display:block; font-weight:900; margin:10px 0 6px 0;">Password</label>
        <input type="password" name="password" required />
        <button class="btn btn-primary" type="submit" style="margin-top:12px;">Log In</button>
      </form>
      <p class="muted" style="margin-top:10px;">Need an account? <a class="btn-link" href="/company/signup">Sign up</a></p>
    </div>
    """
    return _html_page("Company Login", body)


@app.post("/company/login")
def company_login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    _ensure_company_auth_tables(db)
    cu = db.execute(
        text(
            """
            SELECT id, password_hash, is_active
            FROM company_users
            WHERE email = :email
            """
        ),
        {"email": (email or "").strip().lower()},
    ).mappings().first()

    if not cu or not cu["is_active"] or not bcrypt.verify((password or "").strip(), cu["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = secrets.token_urlsafe(32)
    token_hash = _hash_token(token)
    db.execute(
        text(
            """
            INSERT INTO company_sessions (company_user_id, token_hash, user_agent, ip)
            VALUES (:company_user_id, :token_hash, :ua, :ip)
            """
        ),
        {
            "company_user_id": cu["id"],
            "token_hash": token_hash,
            "ua": request.headers.get("user-agent"),
            "ip": request.client.host if request.client else None,
        },
    )
    db.commit()

    resp = RedirectResponse(url="/company", status_code=302)
    _set_cookie(resp, COMPANY_SESSION_COOKIE, token)
    return resp


@app.post("/company/logout")
def company_logout(request: Request, db: Session = Depends(get_db)):
    _ensure_company_auth_tables(db)
    token = request.cookies.get(COMPANY_SESSION_COOKIE)
    resp = RedirectResponse(url="/company/login", status_code=302)
    if token:
        db.execute(text("UPDATE company_sessions SET revoked_at = now() WHERE token_hash = :th"), {"th": _hash_token(token)})
        db.commit()
    _clear_cookie(resp, COMPANY_SESSION_COOKIE)
    return resp


@app.get("/company", response_class=HTMLResponse)
def company_dashboard(
    db: Session = Depends(get_db),
    company_user=Depends(get_current_company_user),
):
    company = _get_company(db, company_user["company_code"])
    service_pro_count = db.execute(text("SELECT COUNT(*) FROM techs WHERE company_id = :id"), {"id": company["id"]}).scalar_one()
    ratings_30d = db.execute(
        text("SELECT COUNT(*) FROM ratings WHERE company_id = :id AND created_at >= now() - interval '30 days'"),
        {"id": company["id"]},
    ).scalar_one()
    open_feedback = db.execute(text("SELECT COUNT(*) FROM feedback WHERE company_id = :id AND status='open'"), {"id": company["id"]}).scalar_one()

    right = """
      <a class="btn" style="width:auto; padding:10px 12px;" href="/company/service-pros">Service Pros</a>
      <a class="btn" style="width:auto; padding:10px 12px;" href="/company/feedback">Feedback Inbox</a>
      <a class="btn" style="width:auto; padding:10px 12px;" href="/company/settings">Settings</a>
      <form method="post" action="/company/logout" style="margin:0;">
        <button class="btn" style="width:auto; padding:10px 12px;" type="submit">Logout</button>
      </form>
    """

    body = f"""
    <h1>{html.escape(company['name'])}</h1>
    <p class="muted">Company dashboard for self-service setup and branding.</p>
    <div class="grid two">
      <div class="card"><div class="pill">Service Pros</div><h2 style="font-size:28px; margin:10px 0 0 0;">{int(service_pro_count or 0)}</h2></div>
      <div class="card"><div class="pill">Ratings (30d)</div><h2 style="font-size:28px; margin:10px 0 0 0;">{int(ratings_30d or 0)}</h2></div>
      <div class="card"><div class="pill">Open Feedback</div><h2 style="font-size:28px; margin:10px 0 0 0;">{int(open_feedback or 0)}</h2></div>
      <div class="card"><div class="pill">Public Base URL</div><p class="muted" style="margin-top:10px;">/t/{company['code']}/&lt;service-pro-slug&gt;</p></div>
    </div>
    <div class="card" style="margin-top:12px;">
      <div class="pill">Next step</div>
      <p class="muted" style="margin-top:10px;">Use Settings to customize your public page branding and office contact data.</p>
      <div class="row">
        <a class="btn btn-primary" style="width:auto;" href="/company/settings">Open Company Settings</a>
        <a class="btn" style="width:auto;" href="/company/service-pros">Manage Service Pros</a>
        <a class="btn" style="width:auto;" href="/company/feedback">Open Feedback Inbox</a>
      </div>
    </div>
    """
    return _html_page("Company Dashboard", body, right_html=right, **_company_branding_kwargs(company))


@app.get("/company/settings", response_class=HTMLResponse)
def company_settings_page(
    db: Session = Depends(get_db),
    company_user=Depends(get_current_company_user),
):
    company = _get_company(db, company_user["company_code"])
    missing_brand_cols = [c for c in _company_branding_columns() if not _has_column(db, "companies", c)]

    def v(key: str) -> str:
        return html.escape((company.get(key) or "").strip(), quote=True)

    right = """
      <a class="btn" style="width:auto; padding:10px 12px;" href="/company">Dashboard</a>
      <a class="btn" style="width:auto; padding:10px 12px;" href="/company/service-pros">Service Pros</a>
      <a class="btn" style="width:auto; padding:10px 12px;" href="/company/feedback">Feedback Inbox</a>
      <form method="post" action="/company/logout" style="margin:0;">
        <button class="btn" style="width:auto; padding:10px 12px;" type="submit">Logout</button>
      </form>
    """

    missing_brand_html = ""
    if missing_brand_cols:
        missing_brand_html = f"""
        <div class="card" style="border-color:#efab16; background:#fffaf0; margin-bottom:12px;">
          <div class="pill">Database migration needed</div>
          <p class="muted" style="margin-top:10px;">
            Branding fields are read-only until these columns exist:
            <code>{html.escape(', '.join(missing_brand_cols))}</code>
          </p>
        </div>
        """

    body = f"""
    <h1>Company Settings</h1>
    <p class="muted">Edit office details and branding for your public Service Pro pages.</p>
    {missing_brand_html}
    <div class="card">
      <form method="post" action="/company/settings" enctype="multipart/form-data">
        <div class="grid two">
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Company name</label>
            <input name="name" required value="{v('name')}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Company code</label>
            <input name="code" required maxlength="20" value="{v('code')}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Office phone (E.164)</label>
            <input name="phone_e164" required value="{v('phone_e164')}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Review mode hours</label>
            <input name="review_mode_hours" type="number" min="1" max="168" value="{int(company.get('review_mode_hours') or 24)}" required />
          </div>
          <div style="grid-column:1/-1;">
            <label style="display:block; font-weight:900; margin-bottom:6px;">Google review URL</label>
            <input name="google_review_url" required value="{v('google_review_url')}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Email</label>
            <input name="email" value="{v('email')}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Website</label>
            <input name="website" value="{v('website')}" />
          </div>
          <div style="grid-column:1/-1;"><div class="hr"></div><div class="pill">Branding</div></div>
          <div style="grid-column:1/-1;">
            <label style="display:block; font-weight:900; margin-bottom:6px;">Brand logo URL</label>
            <input name="brand_logo_url" placeholder="https://..." value="{v('brand_logo_url')}" />
          </div>
          <div style="grid-column:1/-1;">
            <label style="display:block; font-weight:900; margin-bottom:6px;">Or upload logo image</label>
            <input type="file" name="brand_logo_file" accept=".jpg,.jpeg,.png,.webp,image/jpeg,image/png,image/webp" />
            <p class="muted" style="margin-top:6px;">PNG/JPG/WebP up to 5MB.</p>
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Primary color</label>
            <input name="brand_primary_color" placeholder="#142030" value="{v('brand_primary_color')}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Accent color</label>
            <input name="brand_accent_color" placeholder="#efab16" value="{v('brand_accent_color')}" />
          </div>
          <div style="grid-column:1/-1;">
            <label style="display:block; font-weight:900; margin-bottom:6px;">Brand tagline</label>
            <input name="brand_tagline" placeholder="Your trust statement" value="{v('brand_tagline')}" />
          </div>
        </div>
        <button class="btn btn-primary" type="submit" style="margin-top:12px;">Save Settings</button>
      </form>
    </div>
    """
    return _html_page("Company Settings", body, right_html=right, **_company_branding_kwargs(company))


@app.post("/company/settings")
def company_settings_save(
    name: str = Form(...),
    code: str = Form(...),
    phone_e164: str = Form(...),
    google_review_url: str = Form(...),
    review_mode_hours: int = Form(...),
    email: str = Form(None),
    website: str = Form(None),
    brand_logo_url: str = Form(None),
    brand_logo_file: UploadFile | None = File(None),
    brand_primary_color: str = Form(None),
    brand_accent_color: str = Form(None),
    brand_tagline: str = Form(None),
    db: Session = Depends(get_db),
    company_user=Depends(get_current_company_user),
):
    code_norm = (code or "").strip().upper()
    if not re.match(r"^[A-Z0-9_-]{3,20}$", code_norm):
        raise HTTPException(status_code=400, detail="Invalid company code format")

    params = {
        "id": company_user["company_id"],
        "name": (name or "").strip(),
        "code": code_norm,
        "phone_e164": (phone_e164 or "").strip(),
        "google_review_url": (google_review_url or "").strip(),
        "review_mode_hours": int(review_mode_hours or 24),
        "email": (email or "").strip() or None,
        "website": (website or "").strip() or None,
    }

    set_parts = [
        "name=:name",
        "code=:code",
        "phone_e164=:phone_e164",
        "google_review_url=:google_review_url",
        "review_mode_hours=:review_mode_hours",
        "email=:email",
        "website=:website",
    ]

    optional_incoming = {
        "brand_logo_url": (brand_logo_url or "").strip() or None,
        "brand_primary_color": (brand_primary_color or "").strip() or None,
        "brand_accent_color": (brand_accent_color or "").strip() or None,
        "brand_tagline": (brand_tagline or "").strip() or None,
    }
    uploaded_logo = _save_uploaded_image(brand_logo_file, f"company-{company_user['company_id']}", "logo")
    if uploaded_logo:
        optional_incoming["brand_logo_url"] = uploaded_logo
    for col, value in optional_incoming.items():
        if _has_column(db, "companies", col):
            set_parts.append(f"{col}=:{col}")
            params[col] = value

    db.execute(text(f"UPDATE companies SET {', '.join(set_parts)} WHERE id=:id"), params)
    db.commit()
    return RedirectResponse(url="/company/settings", status_code=302)


@app.get("/company/service-pros", response_class=HTMLResponse)
def company_service_pros_page(
    db: Session = Depends(get_db),
    company_user=Depends(get_current_company_user),
):
    company = _get_company(db, company_user["company_code"])

    tech_rows = db.execute(
        text(
            """
            SELECT id, name, role, slug, status, license_number
            FROM techs
            WHERE company_id = :company_id
            ORDER BY name ASC
            """
        ),
        {"company_id": company_user["company_id"]},
    ).mappings().all()

    tech_list = ""
    for t in tech_rows:
        public_link = f"/t/{company['code']}/{t['slug']}"
        tech_list += f"""
          <tr>
            <td>{html.escape(t['name'])}</td>
            <td>{html.escape(t['role'])}</td>
            <td>{html.escape(t['slug'])}</td>
            <td>{html.escape(t['status'])}</td>
            <td><a class="btn-link" href="{public_link}" target="_blank">Open</a></td>
            <td>
              <div class="row" style="gap:8px;">
                <a class="btn" style="width:auto; padding:8px 10px; border-radius:12px;" href="/company/service-pros/{t['id']}/edit">Edit</a>
                <form method="post" action="/company/service-pros/{t['id']}/toggle" style="margin:0;">
                  <button class="btn" style="width:auto; padding:8px 10px; border-radius:12px;" type="submit">Toggle</button>
                </form>
                <form method="post" action="/company/service-pros/{t['id']}/reset-pin" style="margin:0;">
                  <input name="new_pin" placeholder="PIN" maxlength="6" style="width:88px; padding:8px;" required />
                  <button class="btn" style="width:auto; padding:8px 10px; border-radius:12px;" type="submit">PIN</button>
                </form>
                <form method="post" action="/company/service-pros/{t['id']}/delete" style="margin:0;" onsubmit="return confirm('Delete Service Pro {html.escape(t['name'], quote=True)}?');">
                  <button class="btn" style="width:auto; padding:8px 10px; border-radius:12px;" type="submit">Delete</button>
                </form>
              </div>
            </td>
          </tr>
        """

    right = """
      <a class="btn" style="width:auto; padding:10px 12px;" href="/company">Dashboard</a>
      <a class="btn" style="width:auto; padding:10px 12px;" href="/company/feedback">Feedback Inbox</a>
      <a class="btn" style="width:auto; padding:10px 12px;" href="/company/settings">Settings</a>
      <form method="post" action="/company/logout" style="margin:0;">
        <button class="btn" style="width:auto; padding:10px 12px;" type="submit">Logout</button>
      </form>
    """

    body = f"""
    <h1>Service Pros</h1>
    <p class="muted">Manage your team roster and public verification pages.</p>

    <div class="card">
      <div class="pill">Add Service Pro</div>
      <form method="post" action="/company/service-pros/create" style="margin-top:10px;" enctype="multipart/form-data">
        <div class="grid two">
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Name</label>
            <input name="name" required />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Role</label>
            <input name="role" required placeholder="Service Professional" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Slug</label>
            <input name="slug" required placeholder="jane" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">PIN</label>
            <input name="pin" required maxlength="6" inputmode="numeric" />
          </div>
          <div style="grid-column:1/-1;">
            <label style="display:block; font-weight:900; margin-bottom:6px;">License # (optional)</label>
            <input name="license_number" />
          </div>
          <div style="grid-column:1/-1;">
            <label style="display:block; font-weight:900; margin-bottom:6px;">Photo URL (optional)</label>
            <input name="photo_url" />
          </div>
          <div style="grid-column:1/-1;">
            <label style="display:block; font-weight:900; margin-bottom:6px;">Or upload photo (optional)</label>
            <input type="file" name="photo_file" accept=".jpg,.jpeg,.png,.webp,image/jpeg,image/png,image/webp" />
            <p class="muted" style="margin-top:6px;">PNG/JPG/WebP up to 5MB.</p>
          </div>
        </div>
        <button class="btn btn-primary" style="margin-top:12px;" type="submit">Create Service Pro</button>
      </form>
    </div>

    <h2>Roster</h2>
    <div class="card" style="padding:0; overflow:auto;">
      <table>
        <thead><tr><th>Name</th><th>Role</th><th>Slug</th><th>Status</th><th>Public</th><th>Actions</th></tr></thead>
        <tbody>{tech_list or "<tr><td colspan='6' class='muted'>No Service Pros yet.</td></tr>"}</tbody>
      </table>
    </div>
    """
    return _html_page("Company Service Pros", body, right_html=right, **_company_branding_kwargs(company))


@app.post("/company/service-pros/create")
def company_service_pro_create(
    name: str = Form(...),
    role: str = Form(...),
    slug: str = Form(...),
    pin: str = Form(...),
    license_number: str = Form(None),
    photo_url: str = Form(None),
    photo_file: UploadFile | None = File(None),
    db: Session = Depends(get_db),
    company_user=Depends(get_current_company_user),
):
    pin_norm = (pin or "").strip()
    if len(pin_norm) < 4:
        raise HTTPException(status_code=400, detail="PIN too short")

    params = {
        "company_id": company_user["company_id"],
        "name": (name or "").strip(),
        "role": (role or "").strip(),
        "slug": (slug or "").strip().lower().replace(" ", "-"),
        "license_number": (license_number or "").strip() or None,
        "pin_hash": bcrypt.hash(pin_norm),
    }
    photo_val = (photo_url or "").strip() or None
    uploaded_photo = _save_uploaded_image(photo_file, f"company-{company_user['company_id']}", "tech-photo")
    if uploaded_photo:
        photo_val = uploaded_photo

    insert_columns = ["company_id", "name", "role", "slug", "license_number", "status", "pin_hash"]
    insert_values = [":company_id", ":name", ":role", ":slug", ":license_number", "'active'", ":pin_hash"]
    if _has_column(db, "techs", "photo_url"):
        insert_columns.append("photo_url")
        insert_values.append(":photo_url")
        params["photo_url"] = photo_val

    db.execute(text(f"INSERT INTO techs ({', '.join(insert_columns)}) VALUES ({', '.join(insert_values)})"), params)
    db.commit()
    return RedirectResponse(url="/company/service-pros", status_code=302)


@app.get("/company/service-pros/{tech_id}/edit", response_class=HTMLResponse)
def company_service_pro_edit_page(
    tech_id: str,
    db: Session = Depends(get_db),
    company_user=Depends(get_current_company_user),
):
    company = _get_company(db, company_user["company_code"])
    tech = db.execute(
        text(
            """
            SELECT id, name, role, slug, license_number, status
            FROM techs
            WHERE id=:id AND company_id=:company_id
            """
        ),
        {"id": tech_id, "company_id": company_user["company_id"]},
    ).mappings().first()
    if not tech:
        raise HTTPException(status_code=404, detail="Service Pro not found")

    profile_cols = [c for c in _tech_optional_profile_columns() if _has_column(db, "techs", c)]
    profile = {}
    if profile_cols:
        profile = db.execute(text(f"SELECT {', '.join(profile_cols)} FROM techs WHERE id=:id"), {"id": tech_id}).mappings().first() or {}

    def pv(k: str) -> str:
        return html.escape((profile.get(k) or "").strip(), quote=True)

    right = """
      <a class="btn" style="width:auto; padding:10px 12px;" href="/company/service-pros">Service Pros</a>
      <a class="btn" style="width:auto; padding:10px 12px;" href="/company/feedback">Feedback Inbox</a>
      <a class="btn" style="width:auto; padding:10px 12px;" href="/company/settings">Settings</a>
      <form method="post" action="/company/logout" style="margin:0;">
        <button class="btn" style="width:auto; padding:10px 12px;" type="submit">Logout</button>
      </form>
    """
    body = f"""
    <h1>Edit Service Pro</h1>
    <p class="muted">{html.escape(tech['name'])} • {html.escape(tech['role'])}</p>
    <div class="card">
      <form method="post" action="/company/service-pros/{tech_id}/edit" enctype="multipart/form-data">
        <div class="grid two">
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Name</label>
            <input name="name" required value="{html.escape(tech['name'], quote=True)}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Role</label>
            <input name="role" required value="{html.escape(tech['role'], quote=True)}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Slug</label>
            <input name="slug" required value="{html.escape(tech['slug'], quote=True)}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Status</label>
            <select name="status" required>
              <option value="active" {'selected' if tech['status']=='active' else ''}>active</option>
              <option value="disabled" {'selected' if tech['status']=='disabled' else ''}>disabled</option>
            </select>
          </div>
          <div style="grid-column:1/-1;">
            <label style="display:block; font-weight:900; margin-bottom:6px;">License #</label>
            <input name="license_number" value="{html.escape(tech.get('license_number') or '', quote=True)}" />
          </div>
          <div style="grid-column:1/-1;"><div class="hr"></div><div class="pill">Profile + payment links</div></div>
          <div style="grid-column:1/-1;">
            <label style="display:block; font-weight:900; margin-bottom:6px;">Photo URL</label>
            <input name="photo_url" value="{pv('photo_url')}" />
          </div>
          <div style="grid-column:1/-1;">
            <label style="display:block; font-weight:900; margin-bottom:6px;">Or upload photo</label>
            <input type="file" name="photo_file" accept=".jpg,.jpeg,.png,.webp,image/jpeg,image/png,image/webp" />
            <p class="muted" style="margin-top:6px;">PNG/JPG/WebP up to 5MB.</p>
          </div>
          <div style="grid-column:1/-1;">
            <label style="display:block; font-weight:900; margin-bottom:6px;">Short bio</label>
            <textarea name="bio_short" rows="3">{pv('bio_short')}</textarea>
          </div>
          <div><label style="display:block; font-weight:900; margin-bottom:6px;">Venmo</label><input name="venmo_url" value="{pv('venmo_url')}" /></div>
          <div><label style="display:block; font-weight:900; margin-bottom:6px;">Zelle</label><input name="zelle_url" value="{pv('zelle_url')}" /></div>
          <div><label style="display:block; font-weight:900; margin-bottom:6px;">PayPal</label><input name="paypal_url" value="{pv('paypal_url')}" /></div>
          <div><label style="display:block; font-weight:900; margin-bottom:6px;">Cash App</label><input name="cashapp_url" value="{pv('cashapp_url')}" /></div>
          <div><label style="display:block; font-weight:900; margin-bottom:6px;">Apple Pay</label><input name="apple_pay_url" value="{pv('apple_pay_url')}" /></div>
          <div><label style="display:block; font-weight:900; margin-bottom:6px;">Google Pay</label><input name="google_pay_url" value="{pv('google_pay_url')}" /></div>
        </div>
        <div class="row" style="margin-top:12px;">
          <button class="btn btn-primary" style="width:auto;" type="submit">Save Service Pro</button>
          <a class="btn" style="width:auto;" href="/company/service-pros">Back</a>
        </div>
      </form>
    </div>
    """
    return _html_page("Edit Service Pro", body, right_html=right, **_company_branding_kwargs(company))


@app.post("/company/service-pros/{tech_id}/edit")
def company_service_pro_edit(
    tech_id: str,
    name: str = Form(...),
    role: str = Form(...),
    slug: str = Form(...),
    status: str = Form(...),
    license_number: str = Form(None),
    photo_url: str = Form(None),
    photo_file: UploadFile | None = File(None),
    bio_short: str = Form(None),
    venmo_url: str = Form(None),
    zelle_url: str = Form(None),
    paypal_url: str = Form(None),
    cashapp_url: str = Form(None),
    apple_pay_url: str = Form(None),
    google_pay_url: str = Form(None),
    db: Session = Depends(get_db),
    company_user=Depends(get_current_company_user),
):
    exists = db.execute(
        text("SELECT id FROM techs WHERE id=:id AND company_id=:company_id"),
        {"id": tech_id, "company_id": company_user["company_id"]},
    ).scalar()
    if not exists:
        raise HTTPException(status_code=404, detail="Service Pro not found")

    params = {
        "id": tech_id,
        "company_id": company_user["company_id"],
        "name": (name or "").strip(),
        "role": (role or "").strip(),
        "slug": (slug or "").strip().lower().replace(" ", "-"),
        "status": "active" if status == "active" else "disabled",
        "license_number": (license_number or "").strip() or None,
    }
    set_parts = [
        "name=:name",
        "role=:role",
        "slug=:slug",
        "status=:status",
        "license_number=:license_number",
    ]
    optional_incoming = {
        "photo_url": (photo_url or "").strip() or None,
        "bio_short": (bio_short or "").strip() or None,
        "venmo_url": (venmo_url or "").strip() or None,
        "zelle_url": (zelle_url or "").strip() or None,
        "paypal_url": (paypal_url or "").strip() or None,
        "cashapp_url": (cashapp_url or "").strip() or None,
        "apple_pay_url": (apple_pay_url or "").strip() or None,
        "google_pay_url": (google_pay_url or "").strip() or None,
    }
    uploaded_photo = _save_uploaded_image(photo_file, f"company-{company_user['company_id']}", "tech-photo")
    if uploaded_photo:
        optional_incoming["photo_url"] = uploaded_photo
    for col, val in optional_incoming.items():
        if _has_column(db, "techs", col):
            set_parts.append(f"{col}=:{col}")
            params[col] = val

    db.execute(
        text(f"UPDATE techs SET {', '.join(set_parts)} WHERE id=:id AND company_id=:company_id"),
        params,
    )
    db.commit()
    return RedirectResponse(url="/company/service-pros", status_code=302)


@app.post("/company/service-pros/{tech_id}/toggle")
def company_service_pro_toggle(
    tech_id: str,
    db: Session = Depends(get_db),
    company_user=Depends(get_current_company_user),
):
    tech = db.execute(
        text("SELECT status FROM techs WHERE id=:id AND company_id=:company_id"),
        {"id": tech_id, "company_id": company_user["company_id"]},
    ).mappings().first()
    if not tech:
        raise HTTPException(status_code=404, detail="Service Pro not found")
    new_status = "disabled" if tech["status"] == "active" else "active"
    db.execute(
        text("UPDATE techs SET status=:status WHERE id=:id AND company_id=:company_id"),
        {"status": new_status, "id": tech_id, "company_id": company_user["company_id"]},
    )
    db.commit()
    return RedirectResponse(url="/company/service-pros", status_code=302)


@app.post("/company/service-pros/{tech_id}/reset-pin")
def company_service_pro_reset_pin(
    tech_id: str,
    new_pin: str = Form(...),
    db: Session = Depends(get_db),
    company_user=Depends(get_current_company_user),
):
    pin_norm = (new_pin or "").strip()
    if len(pin_norm) < 4:
        raise HTTPException(status_code=400, detail="PIN too short")
    db.execute(
        text("UPDATE techs SET pin_hash=:pin_hash WHERE id=:id AND company_id=:company_id"),
        {"pin_hash": bcrypt.hash(pin_norm), "id": tech_id, "company_id": company_user["company_id"]},
    )
    db.commit()
    return RedirectResponse(url="/company/service-pros", status_code=302)


@app.post("/company/service-pros/{tech_id}/delete")
def company_service_pro_delete(
    tech_id: str,
    db: Session = Depends(get_db),
    company_user=Depends(get_current_company_user),
):
    refs = db.execute(
        text(
            """
            SELECT
              (SELECT COUNT(*) FROM ratings WHERE tech_id = :id) +
              (SELECT COUNT(*) FROM feedback WHERE tech_id = :id) +
              (SELECT COUNT(*) FROM visits WHERE tech_id = :id) AS ref_count
            """
        ),
        {"id": tech_id},
    ).scalar_one()
    if int(refs or 0) > 0:
        raise HTTPException(status_code=400, detail="Cannot delete Service Pro with historical activity")

    db.execute(text("DELETE FROM device_sessions WHERE tech_id=:id"), {"id": tech_id})
    deleted = db.execute(
        text("DELETE FROM techs WHERE id=:id AND company_id=:company_id"),
        {"id": tech_id, "company_id": company_user["company_id"]},
    ).rowcount
    db.commit()
    if not deleted:
        raise HTTPException(status_code=404, detail="Service Pro not found")
    return RedirectResponse(url="/company/service-pros", status_code=302)


# -----------------------------
# COMPANY: Feedback Inbox (Open + Resolved)
# -----------------------------
@app.get("/company/feedback", response_class=HTMLResponse)
def company_feedback_inbox(
    db: Session = Depends(get_db),
    company_user=Depends(get_current_company_user),
):
    open_rows = db.execute(
        text(
            """
            SELECT f.id, f.message, f.status, f.created_at,
                   r.score,
                   t.name AS tech_name, t.slug AS tech_slug
            FROM feedback f
            JOIN ratings r ON r.id = f.rating_id
            JOIN techs t ON t.id = f.tech_id
            WHERE f.company_id = :company_id
              AND f.status = 'open'
            ORDER BY f.created_at DESC
            LIMIT 200
            """
        ),
        {"company_id": company_user["company_id"]},
    ).mappings().all()

    resolved_rows = db.execute(
        text(
            """
            SELECT f.id, f.message, f.status, f.created_at,
                   r.score,
                   t.name AS tech_name, t.slug AS tech_slug
            FROM feedback f
            JOIN ratings r ON r.id = f.rating_id
            JOIN techs t ON t.id = f.tech_id
            WHERE f.company_id = :company_id
              AND f.status = 'resolved'
            ORDER BY f.created_at DESC
            LIMIT 200
            """
        ),
        {"company_id": company_user["company_id"]},
    ).mappings().all()

    company = _get_company(db, company_user["company_code"])

    def render_rows(rows, mode: str) -> str:
        if not rows:
            return "<p class='muted' style='margin:0;'>None.</p>"

        out = "<div class='grid' style='gap:12px;'>"
        for r in rows:
            public_link = f"/t/{company['code']}/{r['tech_slug']}"
            if mode == "open":
                action = f"""
                <form method="post" action="/company/feedback/{r['id']}/resolve" style="margin:0;">
                  <button class="btn" style="width:auto;">Mark Resolved</button>
                </form>
                """
                pill = "<span class='pill'>Open</span>"
            else:
                action = f"""
                <form method="post" action="/company/feedback/{r['id']}/reopen" style="margin:0;">
                  <button class="btn" style="width:auto;">Reopen</button>
                </form>
                """
                pill = "<span class='pill'>Resolved</span>"

            out += f"""
            <div class="card">
              <div class="row" style="justify-content:space-between;">
                <div>
                  <div style="font-weight:900;">{html.escape(r['tech_name'])} • {int(r['score'])}/5</div>
                  <div class="muted" style="font-size:12px; margin-top:2px;">{r['created_at']} • {pill}</div>
                </div>
                <div class="row">{action}<a class="btn" style="width:auto;" href="{public_link}" target="_blank">Open Page</a></div>
              </div>
              <div class="hr"></div>
              <div style="line-height:1.45;">{html.escape(r['message'] or '')}</div>
            </div>
            """
        out += "</div>"
        return out

    right = """
      <a class="btn" style="width:auto; padding:10px 12px;" href="/company">Dashboard</a>
      <a class="btn" style="width:auto; padding:10px 12px;" href="/company/service-pros">Service Pros</a>
      <a class="btn" style="width:auto; padding:10px 12px;" href="/company/settings">Settings</a>
      <form method="post" action="/company/logout" style="margin:0;">
        <button class="btn" style="width:auto; padding:10px 12px;" type="submit">Logout</button>
      </form>
    """

    body = f"""
    <h1>Feedback Inbox</h1>
    <p class="muted">Open items first. Resolve when handled.</p>

    <h2>Open</h2>
    {render_rows(open_rows, "open")}

    <h2 style="margin-top:18px;">Resolved</h2>
    {render_rows(resolved_rows, "resolved")}
    """
    return _html_page("Company Feedback Inbox", body, right_html=right, **_company_branding_kwargs(company))


@app.post("/company/feedback/{feedback_id}/resolve")
def company_feedback_resolve(
    feedback_id: str,
    db: Session = Depends(get_db),
    company_user=Depends(get_current_company_user),
):
    db.execute(
        text("UPDATE feedback SET status='resolved' WHERE id=:id AND company_id=:company_id"),
        {"id": feedback_id, "company_id": company_user["company_id"]},
    )
    db.commit()
    return RedirectResponse(url="/company/feedback", status_code=302)


@app.post("/company/feedback/{feedback_id}/reopen")
def company_feedback_reopen(
    feedback_id: str,
    db: Session = Depends(get_db),
    company_user=Depends(get_current_company_user),
):
    db.execute(
        text("UPDATE feedback SET status='open' WHERE id=:id AND company_id=:company_id"),
        {"id": feedback_id, "company_id": company_user["company_id"]},
    )
    db.commit()
    return RedirectResponse(url="/company/feedback", status_code=302)


# -----------------------------
# TECH PORTAL: login + pair + app + visits + logout
# -----------------------------
@app.get("/login", response_class=HTMLResponse)
def login_page():
    body = """
    <h1>Service Pro Login</h1>
    <p class="muted">Enter your Company Code and 6-digit PIN.</p>

    <div class="card">
      <form method="post" action="/auth/pair">
        <label style="display:block; font-weight:900; margin-bottom:6px;">Company Code</label>
        <input name="company_code" required />

        <label style="display:block; font-weight:900; margin:12px 0 6px 0;">PIN</label>
        <input name="pin" required inputmode="numeric" maxlength="6" />

        <button class="btn btn-primary" type="submit" style="margin-top:12px;">Pair Device</button>
      </form>
    </div>
    """
    return _html_page("Service Pro Login", body)


@app.post("/auth/pair")
def auth_pair(
    request: Request,
    company_code: str = Form(...),
    pin: str = Form(...),
    db: Session = Depends(get_db),
):
    _enforce_rate_limit(request, "pair")
    company = db.execute(
        text("SELECT id, code, name FROM companies WHERE code = :code"),
        {"code": company_code.upper()},
    ).mappings().first()
    if not company:
        raise HTTPException(status_code=400, detail="Invalid company code")

    tech_rows = db.execute(
        text(
            """
            SELECT id, company_id, name, role, slug, status, pin_hash
            FROM techs
            WHERE company_id = :cid AND status = 'active'
            """
        ),
        {"cid": company["id"]},
    ).mappings().all()

    matched = None
    for t in tech_rows:
        if bcrypt.verify(pin, t["pin_hash"]):
            matched = t
            break

    if not matched:
        raise HTTPException(status_code=401, detail="Invalid PIN")

    token = secrets.token_urlsafe(32)
    token_hash = _hash_token(token)

    db.execute(
        text(
            """
            INSERT INTO device_sessions (tech_id, token_hash, user_agent, ip)
            VALUES (:tech_id, :token_hash, :ua, :ip)
            """
        ),
        {
            "tech_id": matched["id"],
            "token_hash": token_hash,
            "ua": request.headers.get("user-agent"),
            "ip": request.client.host if request.client else None,
        },
    )
    db.commit()

    resp = RedirectResponse(url="/app", status_code=302)
    _set_cookie(resp, TECH_SESSION_COOKIE, token)
    return resp


@app.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get(TECH_SESSION_COOKIE)
    resp = RedirectResponse(url="/login", status_code=302)

    if token:
        token_hash = _hash_token(token)
        db.execute(text("UPDATE device_sessions SET revoked_at = now() WHERE token_hash = :th"), {"th": token_hash})
        db.commit()

    _clear_cookie(resp, TECH_SESSION_COOKIE)
    return resp


@app.get("/app", response_class=HTMLResponse)
def tech_app_home(
    request: Request,
    db: Session = Depends(get_db),
    tech=Depends(get_current_tech),
):
    company = db.execute(
        text("SELECT code, name, review_mode_hours FROM companies WHERE id=:id"),
        {"id": tech["company_id"]},
    ).mappings().first()

    public_link = f"/t/{company['code']}/{tech['slug']}"
    msg_on_my_way = f"On my way — {tech['name']} with {company['name']}. Verify here: {public_link}"
    msg_verify = f"Quick verification link: {public_link}"
    msg_after_job = f"Thanks again — here’s the link to review today’s service: {public_link}"

    body = f"""
    <h1>Hey, {tech['name']}.</h1>
    <p class="muted">Your public link (QR/NFC destination):</p>

    <div class="card">
      <div style="font-weight:900;">{public_link}</div>
      <p class="muted" style="margin-top:8px;">Use this link on your badge, QR, or NFC tap.</p>
    </div>

    <h2>Share Templates</h2>
    <div class="card">
      <div style="font-weight:900;">On my way</div>
      <p class="muted">{msg_on_my_way}</p>
      <button class="btn btn-soft" style="width:auto;" type="button" onclick="navigator.clipboard.writeText(this.dataset.copy)" data-copy="{html.escape(msg_on_my_way, quote=True)}">Copy</button>

      <div class="hr"></div>

      <div style="font-weight:900;">Verification</div>
      <p class="muted">{msg_verify}</p>
      <button class="btn btn-soft" style="width:auto;" type="button" onclick="navigator.clipboard.writeText(this.dataset.copy)" data-copy="{html.escape(msg_verify, quote=True)}">Copy</button>

      <div class="hr"></div>

      <div style="font-weight:900;">After job</div>
      <p class="muted" style="margin-bottom:0;">{msg_after_job}</p>
      <button class="btn btn-soft" style="width:auto; margin-top:10px;" type="button" onclick="navigator.clipboard.writeText(this.dataset.copy)" data-copy="{html.escape(msg_after_job, quote=True)}">Copy</button>
    </div>

    <h2>Visit Controls</h2>
    <div class="grid">
      <div class="card">
        <div class="pill">Optional</div>
        <h2 style="margin-top:10px;">Start Visit</h2>

        <form method="post" action="/visits/start">
          <label style="display:block; font-weight:900; margin-bottom:6px;">Customer name (optional)</label>
          <input name="customer_name" />

          <label style="display:block; font-weight:900; margin:12px 0 6px 0;">Customer phone (optional)</label>
          <input name="customer_phone" />

          <button class="btn btn-primary" type="submit" style="margin-top:12px;">Start Visit</button>
        </form>
      </div>

      <div class="card">
        <div class="pill">Important</div>
        <h2 style="margin-top:10px;">Complete Visit</h2>
        <p class="muted">
          This flips your public page into <b>Review Mode</b> for {company['review_mode_hours']} hours.
        </p>
        <form method="post" action="/visits/complete">
          <button class="btn btn-primary" type="submit">Complete Visit + Enable Review Mode</button>
        </form>
      </div>

      <form method="post" action="/logout">
        <button class="btn" type="submit">Logout</button>
      </form>
    </div>
    """
    return _html_page("Service Pro Portal", body)


@app.post("/visits/start", response_class=HTMLResponse)
def visits_start(
    request: Request,
    customer_name: str = Form(None),
    customer_phone: str = Form(None),
    db: Session = Depends(get_db),
    tech=Depends(get_current_tech),
):
    db.execute(
        text(
            """
            INSERT INTO visits (company_id, tech_id, customer_name, customer_phone)
            VALUES (:company_id, :tech_id, :customer_name, :customer_phone)
            """
        ),
        {
            "company_id": tech["company_id"],
            "tech_id": tech["id"],
            "customer_name": (customer_name or "").strip() or None,
            "customer_phone": (customer_phone or "").strip() or None,
        },
    )
    db.commit()
    return RedirectResponse(url="/app", status_code=302)


@app.post("/visits/complete", response_class=HTMLResponse)
def visits_complete(
    request: Request,
    db: Session = Depends(get_db),
    tech=Depends(get_current_tech),
):
    visit = db.execute(
        text(
            """
            SELECT id
            FROM visits
            WHERE tech_id = :tech_id AND completed_at IS NULL
            ORDER BY started_at DESC
            LIMIT 1
            """
        ),
        {"tech_id": tech["id"]},
    ).mappings().first()

    if visit:
        db.execute(text("UPDATE visits SET completed_at = now() WHERE id = :id"), {"id": visit["id"]})

    company = db.execute(
        text("SELECT review_mode_hours FROM companies WHERE id = :id"),
        {"id": tech["company_id"]},
    ).mappings().first()

    hours = int(company["review_mode_hours"]) if company else 24

    db.execute(
        text(
            """
            UPDATE techs
            SET review_mode_until = now() + (:hours || ' hours')::interval
            WHERE id = :tech_id
            """
        ),
        {"hours": hours, "tech_id": tech["id"]},
    )
    db.commit()

    return RedirectResponse(url="/app", status_code=302)


# -----------------------------
# ADMIN: login + dashboard + tech ops
# -----------------------------
@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_page():
    body = """
    <h1>Admin Login</h1>
    <p class="muted">Office access only.</p>

    <div class="card">
      <form method="post" action="/admin/login">
        <label style="display:block; font-weight:900; margin-bottom:6px;">Email</label>
        <input name="email" required />

        <label style="display:block; font-weight:900; margin:12px 0 6px 0;">Password</label>
        <input type="password" name="password" required />

        <button class="btn btn-primary" type="submit" style="margin-top:12px;">Sign in</button>
      </form>
    </div>
    """
    return _html_page("Admin Login", body)


@app.post("/admin/login")
def admin_login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    admin = db.execute(
        text("SELECT id, email, password_hash, is_active FROM admin_users WHERE email=:email"),
        {"email": email.strip().lower()},
    ).mappings().first()

    if not admin or not admin["is_active"] or not bcrypt.verify(password, admin["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = secrets.token_urlsafe(32)
    token_hash = _hash_token(token)

    db.execute(
        text(
            """
            INSERT INTO admin_sessions (admin_id, token_hash, user_agent, ip)
            VALUES (:admin_id, :token_hash, :ua, :ip)
            """
        ),
        {
            "admin_id": admin["id"],
            "token_hash": token_hash,
            "ua": request.headers.get("user-agent"),
            "ip": request.client.host if request.client else None,
        },
    )
    db.commit()

    resp = RedirectResponse(url="/admin", status_code=302)
    _set_cookie(resp, ADMIN_SESSION_COOKIE, token)
    return resp


@app.post("/admin/logout")
def admin_logout(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get(ADMIN_SESSION_COOKIE)
    resp = RedirectResponse(url="/admin/login", status_code=302)

    if token:
        token_hash = _hash_token(token)
        db.execute(text("UPDATE admin_sessions SET revoked_at = now() WHERE token_hash = :th"), {"th": token_hash})
        db.commit()

    _clear_cookie(resp, ADMIN_SESSION_COOKIE)
    return resp


@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    companies = db.execute(
        text(
            """
            SELECT c.id, c.name, c.code, c.phone_e164, c.email, c.website, c.review_mode_hours, COUNT(t.id) AS service_pro_count
            FROM companies c
            LEFT JOIN techs t ON t.company_id = c.id
            GROUP BY c.id, c.name, c.code, c.phone_e164, c.email, c.website, c.review_mode_hours
            ORDER BY c.name ASC
            """
        )
    ).mappings().all()
    missing_profile_cols = _missing_optional_tech_columns(db)

    tech_rows = db.execute(
        text(
            """
            SELECT t.id, t.name, t.role, t.slug, t.status, c.code AS company_code, c.name AS company_name
            FROM techs t
            JOIN companies c ON c.id = t.company_id
            ORDER BY c.name ASC, t.name ASC
            """
        )
    ).mappings().all()

    company_options = "".join([f"<option value='{c['id']}'>{c['name']} ({c['code']})</option>" for c in companies])
    company_rows = ""
    for c in companies:
        edit_link = f"/admin/company/{c['id']}/edit"
        company_rows += f"""
          <tr>
            <td>{html.escape(c['name'])}</td>
            <td>{html.escape(c['code'])}</td>
            <td>{html.escape(c['phone_e164'] or '')}</td>
            <td>{int(c['review_mode_hours'] or 24)}</td>
            <td>{int(c['service_pro_count'] or 0)}</td>
            <td style="white-space:nowrap;"><a class="btn-link" href="{edit_link}">Edit</a></td>
            <td style="white-space:nowrap;">
              <form method="post" action="/admin/company/{c['id']}/delete" style="margin:0;" onsubmit="return confirm('Delete company {html.escape(c['name'], quote=True)}? This only works if no Service Pros exist.');">
                <button class="btn" style="width:auto; padding:8px 12px; border-radius:12px; white-space:nowrap;">Delete</button>
              </form>
            </td>
          </tr>
        """

    tech_list = ""
    for t in tech_rows:
        public_link = f"/t/{t['company_code']}/{t['slug']}"
        edit_link = f"/admin/tech/{t['id']}/edit"
        tech_list += f"""
          <tr>
            <td>{t['company_name']}</td>
            <td>{t['name']}</td>
            <td>{t['role']}</td>
            <td>{t['slug']}</td>
            <td>{t['status']}</td>
            <td><a class="btn-link" href="{public_link}" target="_blank">Open</a></td>
            <td>
              <div class="row" style="gap:8px; align-items:center;">
              <form method="post" action="/admin/tech/{t['id']}/reset-pin" style="display:inline-block; margin:0;">
                <input name="new_pin" placeholder="New PIN" maxlength="6"
                       style="width:100px; padding:8px;" required />
                <button class="btn" style="display:inline-block; width:auto; padding:8px 10px; border-radius:12px;">Reset</button>
              </form>

              <form method="post" action="/admin/tech/{t['id']}/revoke-sessions" style="display:inline-block; margin:0;">
                <button class="btn" style="display:inline-block; width:auto; padding:8px 10px; border-radius:12px;">Revoke</button>
              </form>

              <form method="post" action="/admin/tech/{t['id']}/toggle" style="display:inline-block; margin:0;">
                <button class="btn" style="display:inline-block; width:auto; padding:8px 10px; border-radius:12px;">Toggle</button>
              </form>

              <a class="btn" style="display:inline-block; width:auto; padding:8px 10px; border-radius:12px;" href="{edit_link}">Edit</a>
              <form method="post" action="/admin/tech/{t['id']}/delete" style="display:inline-block; margin:0;" onsubmit="return confirm('Delete Service Pro {html.escape(t['name'], quote=True)}?');">
                <button class="btn" style="display:inline-block; width:auto; padding:8px 10px; border-radius:12px;">Delete</button>
              </form>
              </div>
            </td>
          </tr>
        """

    right = """
      <a class="btn" style="width:auto; padding:10px 12px;" href="/admin/analytics">Analytics</a>
      <a class="btn" style="width:auto; padding:10px 12px;" href="/admin/feedback">Feedback</a>
      <form method="post" action="/admin/logout" style="margin:0;">
        <button class="btn" style="width:auto; padding:10px 12px;" type="submit">Logout</button>
      </form>
    """

    missing_cols_html = ""
    if missing_profile_cols:
        cols = ", ".join(missing_profile_cols)
        missing_cols_html = f"""
        <div class="card" style="border-color:#efab16; background:#fffaf0;">
          <div class="pill">Database migration needed</div>
          <p class="muted" style="margin-top:10px;">
            Profile/payment fields will not save until tech columns exist:
            <code>{html.escape(cols)}</code>
          </p>
        </div>
        """

    body = f"""
    <h1>Admin</h1>
    <p class="muted">Create Service Pros, reset PINs, revoke sessions, and manage feedback.</p>
    {missing_cols_html}

    <h2>Companies</h2>
    <div class="grid two">
      <div class="card">
        <div class="pill">Create Company</div>
        <form method="post" action="/admin/company/create" style="margin-top:10px;">
          <label style="display:block; font-weight:900; margin-bottom:6px;">Company name</label>
          <input name="name" required placeholder="Acme Home Services" />

          <label style="display:block; font-weight:900; margin:10px 0 6px 0;">Company code</label>
          <input name="code" required placeholder="ACME1" maxlength="20" />

          <label style="display:block; font-weight:900; margin:10px 0 6px 0;">Office phone (E.164)</label>
          <input name="phone_e164" required placeholder="+15551234567" />

          <label style="display:block; font-weight:900; margin:10px 0 6px 0;">Google review URL</label>
          <input name="google_review_url" required placeholder="https://..." />

          <label style="display:block; font-weight:900; margin:10px 0 6px 0;">Review mode hours</label>
          <input name="review_mode_hours" type="number" min="1" max="168" value="24" required />

          <label style="display:block; font-weight:900; margin:10px 0 6px 0;">Email (optional)</label>
          <input name="email" placeholder="office@example.com" />

          <label style="display:block; font-weight:900; margin:10px 0 6px 0;">Website (optional)</label>
          <input name="website" placeholder="https://..." />

          <button class="btn btn-primary" type="submit" style="margin-top:12px;">Create Company</button>
        </form>
      </div>

      <div class="card" style="padding:0; overflow:auto;">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Code</th>
              <th>Phone</th>
              <th>Hours</th>
              <th>Pros</th>
              <th style="white-space:nowrap;">Edit</th>
              <th style="white-space:nowrap; min-width:92px;">Delete</th>
            </tr>
          </thead>
          <tbody>
            {company_rows}
          </tbody>
        </table>
      </div>
    </div>

    <h2 style="margin-top:18px;">Create Service Pro</h2>
    <div class="card">
      <div class="pill">New Service Pro</div>
      <form method="post" action="/admin/tech/create" style="margin-top:10px;">
        <label style="display:block; font-weight:900; margin-bottom:6px;">Company</label>
        <select name="company_id" required>
          {company_options}
        </select>

        <div class="grid two" style="margin-top:12px;">
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Service Pro name</label>
            <input name="name" required />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Role</label>
            <input name="role" required placeholder="Service Professional" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Slug</label>
            <input name="slug" required placeholder="mike" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">PIN</label>
            <input name="pin" required maxlength="6" inputmode="numeric" />
          </div>
          <div style="grid-column:1/-1;">
            <label style="display:block; font-weight:900; margin-bottom:6px;">Lic # (optional)</label>
            <input name="license_number" />
          </div>
          <div style="grid-column:1/-1;">
            <label style="display:block; font-weight:900; margin-bottom:6px;">Photo URL (optional)</label>
            <input name="photo_url" placeholder="https://..." />
          </div>
          <div style="grid-column:1/-1;">
            <label style="display:block; font-weight:900; margin-bottom:6px;">Short bio (optional)</label>
            <textarea name="bio_short" rows="3" placeholder="Friendly one-liner shown on the customer page."></textarea>
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Venmo</label>
            <input name="venmo_url" placeholder="@handle or URL" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Zelle</label>
            <input name="zelle_url" placeholder="email/phone or URL" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">PayPal</label>
            <input name="paypal_url" placeholder="paypal.me/... or URL" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Cash App</label>
            <input name="cashapp_url" placeholder="$handle or URL" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Apple Pay</label>
            <input name="apple_pay_url" placeholder="Payment link URL" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Google Pay</label>
            <input name="google_pay_url" placeholder="Payment link URL" />
          </div>
        </div>

        <button class="btn btn-primary" type="submit" style="margin-top:12px;">Create Service Pro</button>
      </form>
    </div>

    <div class="grid two" style="margin-top:12px;">
      <div class="card">
        <div class="pill">Bulk import</div>
        <p class="muted" style="margin-top:10px;">
          CSV headers: <code>company_code,name,role,slug,pin,license_number</code>
        </p>
        <form method="post" action="/admin/tech/import-csv">
          <textarea name="csv_text" rows="7" placeholder="SBHQ1,Jane Doe,Service Professional,jane,123456,LIC-123"></textarea>
          <button class="btn btn-primary" type="submit" style="margin-top:10px;">Import CSV</button>
        </form>
      </div>

      <div class="card">
        <div class="pill">Badge links export</div>
        <p class="muted" style="margin-top:10px;">
          Download all active Service Pro public links for QR/NFC badge generation.
        </p>
        <a class="btn btn-accent" href="/admin/tech/export-links.csv">Download CSV</a>
      </div>
    </div>

    <h2>Service Pros</h2>
    <div class="card" style="padding:0; overflow:auto;">
      <table>
        <thead>
          <tr>
            <th>Company</th>
            <th>Name</th>
            <th>Role</th>
            <th>Slug</th>
            <th>Status</th>
            <th>Public</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {tech_list}
        </tbody>
      </table>
    </div>
    """
    return _html_page("Admin", body, right_html=right)


@app.post("/admin/company/create")
def admin_create_company(
    name: str = Form(...),
    code: str = Form(...),
    phone_e164: str = Form(...),
    google_review_url: str = Form(...),
    review_mode_hours: int = Form(24),
    email: str = Form(None),
    website: str = Form(None),
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    code_norm = (code or "").strip().upper()
    if not re.match(r"^[A-Z0-9_-]{3,20}$", code_norm):
        raise HTTPException(status_code=400, detail="Company code must be 3-20 chars: A-Z, 0-9, _, -")

    if not (phone_e164 or "").strip().startswith("+"):
        raise HTTPException(status_code=400, detail="Phone must be E.164 (start with +)")

    db.execute(
        text(
            """
            INSERT INTO companies (name, code, phone_e164, email, website, google_review_url, review_mode_hours)
            VALUES (:name, :code, :phone_e164, :email, :website, :google_review_url, :review_mode_hours)
            """
        ),
        {
            "name": (name or "").strip(),
            "code": code_norm,
            "phone_e164": (phone_e164 or "").strip(),
            "email": (email or "").strip() or None,
            "website": (website or "").strip() or None,
            "google_review_url": (google_review_url or "").strip(),
            "review_mode_hours": int(review_mode_hours or 24),
        },
    )
    db.commit()
    return RedirectResponse(url="/admin", status_code=302)


@app.get("/admin/company/{company_id}/edit", response_class=HTMLResponse)
def admin_edit_company_page(
    company_id: str,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    company = db.execute(
        text(
            """
            SELECT id, name, code, phone_e164, email, website,
                   address_line1, address_line2, city, state, zip,
                   google_review_url, review_mode_hours
            FROM companies
            WHERE id = :id
            """
        ),
        {"id": company_id},
    ).mappings().first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

    brand_cols = [c for c in _company_branding_columns() if _has_column(db, "companies", c)]
    if brand_cols:
        brand_data = db.execute(
            text(f"SELECT {', '.join(brand_cols)} FROM companies WHERE id = :id"),
            {"id": company_id},
        ).mappings().first() or {}
        company = {**company, **brand_data}

    def v(key: str) -> str:
        return html.escape((company.get(key) or "").strip(), quote=True)

    body = f"""
    <h1>Edit Company</h1>
    <p class="muted">{html.escape(company['name'])} ({html.escape(company['code'])})</p>

    <div class="card">
      <form method="post" action="/admin/company/{company['id']}/edit">
        <div class="grid two">
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Company name</label>
            <input name="name" required value="{v('name')}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Company code</label>
            <input name="code" required maxlength="20" value="{v('code')}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Office phone (E.164)</label>
            <input name="phone_e164" required value="{v('phone_e164')}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Review mode hours</label>
            <input name="review_mode_hours" type="number" min="1" max="168" required value="{int(company['review_mode_hours'] or 24)}" />
          </div>
          <div style="grid-column:1/-1;">
            <label style="display:block; font-weight:900; margin-bottom:6px;">Google review URL</label>
            <input name="google_review_url" required value="{v('google_review_url')}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Email</label>
            <input name="email" value="{v('email')}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Website</label>
            <input name="website" value="{v('website')}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Address line 1</label>
            <input name="address_line1" value="{v('address_line1')}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Address line 2</label>
            <input name="address_line2" value="{v('address_line2')}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">City</label>
            <input name="city" value="{v('city')}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">State</label>
            <input name="state" value="{v('state')}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">ZIP</label>
            <input name="zip" value="{v('zip')}" />
          </div>
          <div style="grid-column:1/-1;"><div class="hr"></div><div class="pill">Branding</div></div>
          <div style="grid-column:1/-1;">
            <label style="display:block; font-weight:900; margin-bottom:6px;">Brand logo URL</label>
            <input name="brand_logo_url" value="{v('brand_logo_url')}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Primary color</label>
            <input name="brand_primary_color" placeholder="#142030" value="{v('brand_primary_color')}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Accent color</label>
            <input name="brand_accent_color" placeholder="#efab16" value="{v('brand_accent_color')}" />
          </div>
          <div style="grid-column:1/-1;">
            <label style="display:block; font-weight:900; margin-bottom:6px;">Brand tagline</label>
            <input name="brand_tagline" value="{v('brand_tagline')}" />
          </div>
        </div>
        <div class="row" style="margin-top:12px;">
          <button class="btn btn-primary" style="width:auto;" type="submit">Save Company</button>
          <a class="btn" style="width:auto;" href="/admin">Back to Admin</a>
        </div>
      </form>
    </div>
    """
    return _html_page("Edit Company", body)


@app.post("/admin/company/{company_id}/edit")
def admin_edit_company(
    company_id: str,
    name: str = Form(...),
    code: str = Form(...),
    phone_e164: str = Form(...),
    google_review_url: str = Form(...),
    review_mode_hours: int = Form(...),
    email: str = Form(None),
    website: str = Form(None),
    address_line1: str = Form(None),
    address_line2: str = Form(None),
    city: str = Form(None),
    state: str = Form(None),
    zip: str = Form(None),
    brand_logo_url: str = Form(None),
    brand_primary_color: str = Form(None),
    brand_accent_color: str = Form(None),
    brand_tagline: str = Form(None),
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    code_norm = (code or "").strip().upper()
    if not re.match(r"^[A-Z0-9_-]{3,20}$", code_norm):
        raise HTTPException(status_code=400, detail="Company code must be 3-20 chars: A-Z, 0-9, _, -")

    params = {
        "id": company_id,
        "name": (name or "").strip(),
        "code": code_norm,
        "phone_e164": (phone_e164 or "").strip(),
        "email": (email or "").strip() or None,
        "website": (website or "").strip() or None,
        "address_line1": (address_line1 or "").strip() or None,
        "address_line2": (address_line2 or "").strip() or None,
        "city": (city or "").strip() or None,
        "state": (state or "").strip() or None,
        "zip": (zip or "").strip() or None,
        "google_review_url": (google_review_url or "").strip(),
        "review_mode_hours": int(review_mode_hours or 24),
    }
    set_parts = [
        "name=:name",
        "code=:code",
        "phone_e164=:phone_e164",
        "email=:email",
        "website=:website",
        "address_line1=:address_line1",
        "address_line2=:address_line2",
        "city=:city",
        "state=:state",
        "zip=:zip",
        "google_review_url=:google_review_url",
        "review_mode_hours=:review_mode_hours",
    ]
    optional_incoming = {
        "brand_logo_url": (brand_logo_url or "").strip() or None,
        "brand_primary_color": (brand_primary_color or "").strip() or None,
        "brand_accent_color": (brand_accent_color or "").strip() or None,
        "brand_tagline": (brand_tagline or "").strip() or None,
    }
    for col, val in optional_incoming.items():
        if _has_column(db, "companies", col):
            set_parts.append(f"{col}=:{col}")
            params[col] = val

    db.execute(text(f"UPDATE companies SET {', '.join(set_parts)} WHERE id=:id"), params)
    db.commit()
    return RedirectResponse(url="/admin", status_code=302)


@app.post("/admin/company/{company_id}/delete")
def admin_delete_company(
    company_id: str,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    linked_techs = db.execute(text("SELECT COUNT(*) FROM techs WHERE company_id=:id"), {"id": company_id}).scalar_one()
    if int(linked_techs or 0) > 0:
        raise HTTPException(status_code=400, detail="Cannot delete company with existing Service Pros")

    db.execute(text("DELETE FROM companies WHERE id=:id"), {"id": company_id})
    db.commit()
    return RedirectResponse(url="/admin", status_code=302)


@app.post("/admin/tech/create")
def admin_create_tech(
    request: Request,
    company_id: str = Form(...),
    name: str = Form(...),
    role: str = Form(...),
    slug: str = Form(...),
    pin: str = Form(...),
    license_number: str = Form(None),
    photo_url: str = Form(None),
    bio_short: str = Form(None),
    venmo_url: str = Form(None),
    zelle_url: str = Form(None),
    paypal_url: str = Form(None),
    cashapp_url: str = Form(None),
    apple_pay_url: str = Form(None),
    google_pay_url: str = Form(None),
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    slug_norm = slug.strip().lower().replace(" ", "-")
    pin_norm = (pin or "").strip()

    if len(pin_norm) < 4:
        raise HTTPException(status_code=400, detail="PIN too short")

    pin_hash = bcrypt.hash(pin_norm)

    params = {
        "company_id": company_id,
        "name": name.strip(),
        "role": role.strip(),
        "slug": slug_norm,
        "license_number": (license_number or "").strip() or None,
        "pin_hash": pin_hash,
    }

    optional_values = {
        "photo_url": (photo_url or "").strip() or None,
        "bio_short": (bio_short or "").strip() or None,
        "venmo_url": (venmo_url or "").strip() or None,
        "zelle_url": (zelle_url or "").strip() or None,
        "paypal_url": (paypal_url or "").strip() or None,
        "cashapp_url": (cashapp_url or "").strip() or None,
        "apple_pay_url": (apple_pay_url or "").strip() or None,
        "google_pay_url": (google_pay_url or "").strip() or None,
    }

    insert_columns = ["company_id", "name", "role", "slug", "license_number", "status", "pin_hash"]
    insert_values = [":company_id", ":name", ":role", ":slug", ":license_number", "'active'", ":pin_hash"]

    for col_name, col_val in optional_values.items():
        if _has_column(db, "techs", col_name):
            insert_columns.append(col_name)
            insert_values.append(f":{col_name}")
            params[col_name] = col_val

    db.execute(
        text(
            f"""
            INSERT INTO techs ({", ".join(insert_columns)})
            VALUES ({", ".join(insert_values)})
            """
        ),
        params,
    )
    db.commit()

    return RedirectResponse(url="/admin", status_code=302)


@app.post("/admin/tech/import-csv")
def admin_import_tech_csv(
    csv_text: str = Form(...),
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    raw = (csv_text or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="CSV required")

    reader = csv.DictReader(StringIO(raw))
    required_cols = {"company_code", "name", "role", "slug", "pin"}
    if not reader.fieldnames or not required_cols.issubset(set(reader.fieldnames)):
        raise HTTPException(status_code=400, detail="Missing required CSV headers")

    companies = db.execute(text("SELECT id, code FROM companies")).mappings().all()
    company_map = {c["code"].upper(): c["id"] for c in companies}

    inserted = 0
    for row in reader:
        company_code = (row.get("company_code") or "").strip().upper()
        company_id = company_map.get(company_code)
        if not company_id:
            continue

        pin_norm = (row.get("pin") or "").strip()
        if len(pin_norm) < 4:
            continue

        db.execute(
            text(
                """
                INSERT INTO techs (company_id, name, role, slug, license_number, status, pin_hash)
                VALUES (:company_id, :name, :role, :slug, :license_number, 'active', :pin_hash)
                """
            ),
            {
                "company_id": company_id,
                "name": (row.get("name") or "").strip(),
                "role": (row.get("role") or "Service Professional").strip(),
                "slug": (row.get("slug") or "").strip().lower().replace(" ", "-"),
                "license_number": (row.get("license_number") or "").strip() or None,
                "pin_hash": bcrypt.hash(pin_norm),
            },
        )
        inserted += 1

    db.commit()
    if inserted == 0:
        raise HTTPException(status_code=400, detail="No valid rows imported")
    return RedirectResponse(url="/admin", status_code=302)


@app.get("/admin/tech/export-links.csv")
def admin_export_tech_links_csv(
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    rows = db.execute(
        text(
            """
            SELECT c.code AS company_code, t.name, t.slug
            FROM techs t
            JOIN companies c ON c.id = t.company_id
            WHERE t.status = 'active'
            ORDER BY c.code ASC, t.name ASC
            """
        )
    ).mappings().all()

    out = StringIO()
    writer = csv.writer(out)
    writer.writerow(["company_code", "service_pro_name", "slug", "public_link"])
    for r in rows:
        writer.writerow(
            [
                r["company_code"],
                r["name"],
                r["slug"],
                f"https://servicebadgehq.com/t/{r['company_code']}/{r['slug']}",
            ]
        )

    csv_body = out.getvalue()
    return Response(
        content=csv_body,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="service-pro-links.csv"'},
    )


@app.get("/admin/tech/{tech_id}/edit", response_class=HTMLResponse)
def admin_edit_tech_page(
    tech_id: str,
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    base_tech = db.execute(
        text(
            """
            SELECT t.id, t.company_id, t.name, t.role, t.slug, t.license_number, t.status, c.name AS company_name, c.code AS company_code
            FROM techs t
            JOIN companies c ON c.id = t.company_id
            WHERE t.id = :id
            """
        ),
        {"id": tech_id},
    ).mappings().first()
    if not base_tech:
        raise HTTPException(status_code=404, detail="Service Pro not found")

    company_rows = db.execute(text("SELECT id, name, code FROM companies ORDER BY name ASC")).mappings().all()
    company_options = "".join(
        [
            (
                f"<option value='{c['id']}' {'selected' if str(c['id']) == str(base_tech['company_id']) else ''}>"
                f"{html.escape(c['name'])} ({html.escape(c['code'])})</option>"
            )
            for c in company_rows
        ]
    )

    profile_cols = [c for c in _tech_optional_profile_columns() if _has_column(db, "techs", c)]
    missing_cols = [c for c in _tech_optional_profile_columns() if c not in profile_cols]
    profile_data = {}
    if profile_cols:
        profile_data = db.execute(
            text(f"SELECT {', '.join(profile_cols)} FROM techs WHERE id = :id"),
            {"id": tech_id},
        ).mappings().first() or {}

    def val(k: str) -> str:
        return html.escape((profile_data.get(k) or "").strip(), quote=True)

    missing_cols_html = ""
    if missing_cols:
        missing_cols_html = f"""
        <div class="card" style="border-color:#efab16; background:#fffaf0; margin-bottom:12px;">
          <div class="pill">Database migration needed</div>
          <p class="muted" style="margin-top:10px;">
            These fields are currently unavailable and will not save: <code>{html.escape(", ".join(missing_cols))}</code>
          </p>
        </div>
        """

    body = f"""
    <h1>Edit Service Pro</h1>
    <p class="muted">{base_tech['name']} ({base_tech['role']}) • {base_tech['company_name']} ({base_tech['company_code']})</p>
    {missing_cols_html}

    <div class="card" style="margin-bottom:12px;">
      <div class="pill">Core details</div>
      <form method="post" action="/admin/tech/{base_tech['id']}/edit-core" style="margin-top:10px;">
        <div class="grid two">
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Company</label>
            <select name="company_id" required>{company_options}</select>
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Status</label>
            <select name="status" required>
              <option value="active" {'selected' if base_tech['status'] == 'active' else ''}>active</option>
              <option value="disabled" {'selected' if base_tech['status'] == 'disabled' else ''}>disabled</option>
            </select>
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Name</label>
            <input name="name" required value="{html.escape(base_tech['name'], quote=True)}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Role</label>
            <input name="role" required value="{html.escape(base_tech['role'], quote=True)}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Slug</label>
            <input name="slug" required value="{html.escape(base_tech['slug'], quote=True)}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">License #</label>
            <input name="license_number" value="{html.escape(base_tech.get('license_number') or '', quote=True)}" />
          </div>
        </div>
        <div class="row" style="margin-top:12px;">
          <button class="btn btn-primary" style="width:auto;" type="submit">Save Core Details</button>
        </div>
      </form>
    </div>

    <div class="card">
      <div class="pill">Profile + payment links</div>
      <form method="post" action="/admin/tech/{base_tech['id']}/edit" style="margin-top:4px;">
        <div class="grid two">
          <div style="grid-column:1/-1;">
            <label style="display:block; font-weight:900; margin-bottom:6px;">Photo URL (optional)</label>
            <input name="photo_url" placeholder="https://..." value="{val('photo_url')}" />
          </div>
          <div style="grid-column:1/-1;">
            <label style="display:block; font-weight:900; margin-bottom:6px;">Short bio (optional)</label>
            <textarea name="bio_short" rows="3" placeholder="Friendly one-liner shown on the customer page.">{val('bio_short')}</textarea>
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Venmo</label>
            <input name="venmo_url" placeholder="@handle or URL" value="{val('venmo_url')}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Zelle</label>
            <input name="zelle_url" placeholder="email/phone or URL" value="{val('zelle_url')}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">PayPal</label>
            <input name="paypal_url" placeholder="paypal.me/... or URL" value="{val('paypal_url')}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Cash App</label>
            <input name="cashapp_url" placeholder="$handle or URL" value="{val('cashapp_url')}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Apple Pay</label>
            <input name="apple_pay_url" placeholder="Payment link URL" value="{val('apple_pay_url')}" />
          </div>
          <div>
            <label style="display:block; font-weight:900; margin-bottom:6px;">Google Pay</label>
            <input name="google_pay_url" placeholder="Payment link URL" value="{val('google_pay_url')}" />
          </div>
        </div>
        <div class="row" style="margin-top:12px;">
          <button class="btn btn-primary" style="width:auto;" type="submit">Save Profile</button>
          <a class="btn" style="width:auto;" href="/admin">Back to Admin</a>
        </div>
      </form>
      <form method="post" action="/admin/tech/{base_tech['id']}/delete" style="margin-top:10px;" onsubmit="return confirm('Delete this Service Pro? This only works if there is no historical activity.');">
        <button class="btn" style="width:auto;" type="submit">Delete Service Pro</button>
      </form>
    </div>
    """
    return _html_page("Edit Service Pro Profile", body)


@app.post("/admin/tech/{tech_id}/edit")
def admin_edit_tech(
    tech_id: str,
    photo_url: str = Form(None),
    bio_short: str = Form(None),
    venmo_url: str = Form(None),
    zelle_url: str = Form(None),
    paypal_url: str = Form(None),
    cashapp_url: str = Form(None),
    apple_pay_url: str = Form(None),
    google_pay_url: str = Form(None),
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    exists = db.execute(text("SELECT id FROM techs WHERE id=:id"), {"id": tech_id}).scalar()
    if not exists:
        raise HTTPException(status_code=404, detail="Service Pro not found")

    incoming = {
        "photo_url": (photo_url or "").strip() or None,
        "bio_short": (bio_short or "").strip() or None,
        "venmo_url": (venmo_url or "").strip() or None,
        "zelle_url": (zelle_url or "").strip() or None,
        "paypal_url": (paypal_url or "").strip() or None,
        "cashapp_url": (cashapp_url or "").strip() or None,
        "apple_pay_url": (apple_pay_url or "").strip() or None,
        "google_pay_url": (google_pay_url or "").strip() or None,
    }

    set_parts = []
    params = {"id": tech_id}
    for col_name, col_val in incoming.items():
        if _has_column(db, "techs", col_name):
            set_parts.append(f"{col_name} = :{col_name}")
            params[col_name] = col_val

    if set_parts:
        db.execute(text(f"UPDATE techs SET {', '.join(set_parts)} WHERE id = :id"), params)
        db.commit()

    return RedirectResponse(url="/admin", status_code=302)


@app.post("/admin/tech/{tech_id}/edit-core")
def admin_edit_tech_core(
    tech_id: str,
    company_id: str = Form(...),
    name: str = Form(...),
    role: str = Form(...),
    slug: str = Form(...),
    license_number: str = Form(None),
    status: str = Form("active"),
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    status_norm = "active" if status == "active" else "disabled"
    slug_norm = (slug or "").strip().lower().replace(" ", "-")

    db.execute(
        text(
            """
            UPDATE techs
            SET company_id=:company_id,
                name=:name,
                role=:role,
                slug=:slug,
                license_number=:license_number,
                status=:status
            WHERE id=:id
            """
        ),
        {
            "id": tech_id,
            "company_id": company_id,
            "name": (name or "").strip(),
            "role": (role or "").strip(),
            "slug": slug_norm,
            "license_number": (license_number or "").strip() or None,
            "status": status_norm,
        },
    )
    db.commit()
    return RedirectResponse(url=f"/admin/tech/{tech_id}/edit", status_code=302)


@app.post("/admin/tech/{tech_id}/delete")
def admin_delete_tech(
    tech_id: str,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    refs = db.execute(
        text(
            """
            SELECT
              (SELECT COUNT(*) FROM ratings WHERE tech_id = :id) +
              (SELECT COUNT(*) FROM feedback WHERE tech_id = :id) +
              (SELECT COUNT(*) FROM visits WHERE tech_id = :id) AS ref_count
            """
        ),
        {"id": tech_id},
    ).scalar_one()

    if int(refs or 0) > 0:
        raise HTTPException(status_code=400, detail="Cannot delete Service Pro with historical activity")

    db.execute(text("DELETE FROM device_sessions WHERE tech_id = :id"), {"id": tech_id})
    deleted = db.execute(text("DELETE FROM techs WHERE id = :id"), {"id": tech_id}).rowcount
    db.commit()
    if not deleted:
        raise HTTPException(status_code=404, detail="Service Pro not found")
    return RedirectResponse(url="/admin", status_code=302)


@app.post("/admin/tech/{tech_id}/reset-pin")
def admin_reset_pin(
    tech_id: str,
    new_pin: str = Form(...),
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    pin_norm = (new_pin or "").strip()
    if len(pin_norm) < 4:
        raise HTTPException(status_code=400, detail="PIN too short")

    pin_hash = bcrypt.hash(pin_norm)
    db.execute(text("UPDATE techs SET pin_hash=:ph WHERE id=:id"), {"ph": pin_hash, "id": tech_id})
    db.commit()
    return RedirectResponse(url="/admin", status_code=302)


@app.post("/admin/tech/{tech_id}/revoke-sessions")
def admin_revoke_sessions(
    tech_id: str,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    db.execute(
        text("UPDATE device_sessions SET revoked_at=now() WHERE tech_id=:id AND revoked_at IS NULL"),
        {"id": tech_id},
    )
    db.commit()
    return RedirectResponse(url="/admin", status_code=302)


@app.post("/admin/tech/{tech_id}/toggle")
def admin_toggle_tech(
    tech_id: str,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    tech = db.execute(text("SELECT status FROM techs WHERE id=:id"), {"id": tech_id}).mappings().first()
    if not tech:
        raise HTTPException(status_code=404, detail="Service Pro not found")

    new_status = "disabled" if tech["status"] == "active" else "active"
    db.execute(text("UPDATE techs SET status=:s WHERE id=:id"), {"s": new_status, "id": tech_id})
    db.commit()
    return RedirectResponse(url="/admin", status_code=302)


@app.get("/admin/analytics", response_class=HTMLResponse)
def admin_analytics(
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    stats = db.execute(
        text(
            """
            SELECT
              (SELECT COUNT(*) FROM ratings WHERE created_at >= now() - interval '30 days') AS ratings_30d,
              (SELECT COUNT(*) FROM ratings WHERE score >= 4 AND created_at >= now() - interval '30 days') AS high_30d,
              (SELECT COUNT(*) FROM ratings WHERE score <= 3 AND created_at >= now() - interval '30 days') AS low_30d,
              (SELECT COUNT(*) FROM feedback WHERE status = 'open') AS feedback_open,
              (SELECT COUNT(*) FROM visits WHERE started_at >= now() - interval '30 days') AS visits_30d,
              (SELECT COUNT(*) FROM visits WHERE completed_at IS NOT NULL AND started_at >= now() - interval '30 days') AS visits_completed_30d
            """
        )
    ).mappings().first()

    leaders = db.execute(
        text(
            """
            SELECT c.name AS company_name, t.name AS service_pro_name, COUNT(r.id) AS rating_count
            FROM ratings r
            JOIN techs t ON t.id = r.tech_id
            JOIN companies c ON c.id = r.company_id
            WHERE r.created_at >= now() - interval '30 days'
            GROUP BY c.name, t.name
            ORDER BY rating_count DESC, c.name ASC, t.name ASC
            LIMIT 10
            """
        )
    ).mappings().all()

    leaders_rows = "".join(
        [
            f"<tr><td>{html.escape(r['company_name'])}</td><td>{html.escape(r['service_pro_name'])}</td><td>{r['rating_count']}</td></tr>"
            for r in leaders
        ]
    ) or "<tr><td colspan='3' class='muted'>No ratings in the last 30 days.</td></tr>"

    high = int(stats["high_30d"] or 0)
    low = int(stats["low_30d"] or 0)
    total = high + low
    happy_rate = f"{(high / total * 100):.1f}%" if total else "0.0%"

    right = """
      <a class="btn" style="width:auto; padding:10px 12px;" href="/admin">Admin</a>
      <a class="btn" style="width:auto; padding:10px 12px;" href="/admin/feedback">Feedback</a>
      <form method="post" action="/admin/logout" style="margin:0;">
        <button class="btn" style="width:auto; padding:10px 12px;" type="submit">Logout</button>
      </form>
    """

    body = f"""
    <h1>Analytics</h1>
    <p class="muted">30-day performance snapshot for reviews, feedback, and visits.</p>

    <div class="grid two">
      <div class="card"><div class="pill">Ratings (30d)</div><h2 style="font-size:28px; margin:10px 0 0 0;">{stats['ratings_30d']}</h2></div>
      <div class="card"><div class="pill">Happy Rating Rate</div><h2 style="font-size:28px; margin:10px 0 0 0;">{happy_rate}</h2></div>
      <div class="card"><div class="pill">Open Feedback</div><h2 style="font-size:28px; margin:10px 0 0 0;">{stats['feedback_open']}</h2></div>
      <div class="card"><div class="pill">Visits Completed (30d)</div><h2 style="font-size:28px; margin:10px 0 0 0;">{stats['visits_completed_30d']} / {stats['visits_30d']}</h2></div>
    </div>

    <h2>Top Service Pros by Ratings (30d)</h2>
    <div class="card" style="padding:0; overflow:auto;">
      <table>
        <thead><tr><th>Company</th><th>Service Pro</th><th>Ratings</th></tr></thead>
        <tbody>{leaders_rows}</tbody>
      </table>
    </div>
    """
    return _html_page("Analytics", body, right_html=right)


# -----------------------------
# ADMIN: Feedback Inbox (Open + Resolved)
# -----------------------------
@app.get("/admin/feedback", response_class=HTMLResponse)
def admin_feedback_inbox(
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    open_rows = db.execute(
        text(
            """
            SELECT f.id, f.message, f.status, f.created_at,
                   r.score,
                   c.name AS company_name, c.code AS company_code,
                   t.name AS tech_name, t.slug AS tech_slug
            FROM feedback f
            JOIN ratings r ON r.id = f.rating_id
            JOIN companies c ON c.id = f.company_id
            JOIN techs t ON t.id = f.tech_id
            WHERE f.status = 'open'
            ORDER BY f.created_at DESC
            LIMIT 200
            """
        )
    ).mappings().all()

    resolved_rows = db.execute(
        text(
            """
            SELECT f.id, f.message, f.status, f.created_at,
                   r.score,
                   c.name AS company_name, c.code AS company_code,
                   t.name AS tech_name, t.slug AS tech_slug
            FROM feedback f
            JOIN ratings r ON r.id = f.rating_id
            JOIN companies c ON c.id = f.company_id
            JOIN techs t ON t.id = f.tech_id
            WHERE f.status = 'resolved'
            ORDER BY f.created_at DESC
            LIMIT 200
            """
        )
    ).mappings().all()

    def esc(s: str) -> str:
        return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def render_rows(rows, mode: str):
        if not rows:
            return "<p class='muted' style='margin:0;'>None.</p>"

        out = "<div class='grid' style='gap:12px;'>"
        for r in rows:
            public_link = f"/t/{r['company_code']}/{r['tech_slug']}"
            if mode == "open":
                action = f"""
                <form method="post" action="/admin/feedback/{r['id']}/resolve" style="margin:0;">
                  <button class="btn" style="width:auto;">Mark Resolved</button>
                </form>
                """
                pill = "<span class='pill'>Open</span>"
            else:
                action = f"""
                <form method="post" action="/admin/feedback/{r['id']}/reopen" style="margin:0;">
                  <button class="btn" style="width:auto;">Reopen</button>
                </form>
                """
                pill = "<span class='pill'>Resolved</span>"

            out += f"""
            <div class="card">
              <div class="row" style="justify-content:space-between;">
                <div>
                  <div style="font-weight:900;">{esc(r['company_name'])} • {esc(r['tech_name'])} • {r['score']}/5</div>
                  <div class="muted" style="font-size:12px; margin-top:2px;">{r['created_at']} • {pill}</div>
                </div>
                <div class="row">{action}<a class="btn" style="width:auto;" href="{public_link}" target="_blank">Open Page</a></div>
              </div>
              <div class="hr"></div>
              <div style="line-height:1.45;">{esc(r['message'])}</div>
            </div>
            """
        out += "</div>"
        return out

    right = """
      <a class="btn" style="width:auto; padding:10px 12px;" href="/admin/analytics">Analytics</a>
      <a class="btn" style="width:auto; padding:10px 12px;" href="/admin">Admin</a>
      <form method="post" action="/admin/logout" style="margin:0;">
        <button class="btn" style="width:auto; padding:10px 12px;" type="submit">Logout</button>
      </form>
    """

    body = f"""
    <h1>Feedback Inbox</h1>
    <p class="muted">Open items first. Resolve when handled.</p>

    <h2>Open</h2>
    {render_rows(open_rows, "open")}

    <h2 style="margin-top:18px;">Resolved</h2>
    {render_rows(resolved_rows, "resolved")}
    """
    return _html_page("Feedback Inbox", body, right_html=right)


@app.post("/admin/feedback/{feedback_id}/resolve")
def admin_feedback_resolve(
    feedback_id: str,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    db.execute(text("UPDATE feedback SET status='resolved' WHERE id=:id"), {"id": feedback_id})
    db.commit()
    return RedirectResponse(url="/admin/feedback", status_code=302)


@app.post("/admin/feedback/{feedback_id}/reopen")
def admin_feedback_reopen(
    feedback_id: str,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    db.execute(text("UPDATE feedback SET status='open' WHERE id=:id"), {"id": feedback_id})
    db.commit()
    return RedirectResponse(url="/admin/feedback", status_code=302)
