from datetime import datetime, timezone
from urllib.parse import quote
import hashlib
import secrets
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException, Form, Request
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


# -----------------------------
# PWA helpers (site-wide)
# -----------------------------
def _pwa_head() -> str:
    """
    Injected into every HTML page so the whole site is installable.
    """
    return """
    <meta name="theme-color" content="#111111" />
    <link rel="manifest" href="/static/manifest.webmanifest" />

    <!-- App icons -->
    <link rel="icon" type="image/png" sizes="192x192" href="/static/icon-192.png" />
    <link rel="icon" type="image/png" sizes="512x512" href="/static/icon-512.png" />

    <!-- iOS "Add to Home Screen" support -->
    <meta name="apple-mobile-web-app-capable" content="yes" />
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
    <meta name="apple-mobile-web-app-title" content="ServiceBadgeHQ" />
    <link rel="apple-touch-icon" href="/static/icon-192.png" />

    <script>
      // Register service worker
      if ('serviceWorker' in navigator) {
        window.addEventListener('load', () => {
          navigator.serviceWorker.register('/static/sw.js').catch(() => {});
        });
      }
    </script>
    """


def _html_page(title: str, body: str) -> str:
    return f"""
    <html>
      <head>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>{title}</title>
        {_pwa_head()}
      </head>
      <body style="margin:0; padding:18px; font-family:system-ui, -apple-system, Segoe UI, Roboto, Arial;">
        {body}
      </body>
    </html>
    """


# -----------------------------
# Helpers: hashing / tokens
# -----------------------------
def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _set_cookie(resp: Response, key: str, token: str):
    # secure=True because we are on HTTPS now
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


# -----------------------------
# Helpers: Company / Tech fetch
# -----------------------------
def _get_company(db: Session, company_code: str):
    return db.execute(
        text(
            """
            SELECT id, name, code, phone_e164, email, website,
                   address_line1, address_line2, city, state, zip,
                   google_review_url, review_mode_hours
            FROM companies
            WHERE code = :code
            """
        ),
        {"code": company_code.upper()},
    ).mappings().first()


def _get_tech(db: Session, company_id, tech_slug: str):
    return db.execute(
        text(
            """
            SELECT id, name, role, slug, photo_url, license_number, status, review_mode_until, pin_hash
            FROM techs
            WHERE company_id = :company_id AND slug = :slug
            """
        ),
        {"company_id": company_id, "slug": tech_slug.lower()},
    ).mappings().first()


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
        raise HTTPException(status_code=401, detail="Tech not found")

    if tech["status"] != "active":
        raise HTTPException(status_code=403, detail="Tech disabled")

    db.execute(
        text("UPDATE device_sessions SET last_seen_at = now() WHERE token_hash = :th"),
        {"th": token_hash},
    )
    db.commit()

    return tech


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
# UI: Sticky office-only contact bar
# -----------------------------
def _contact_bar_html(company_code: str, phone_e164: str, phone_display: str, sms_body: str) -> str:
    sms_link = f"sms:{phone_e164}?body={quote(sms_body)}"
    tel_link = f"tel:{phone_e164}"
    vcard_link = f"/c/{company_code.upper()}/office.vcf"

    return f"""
    <div style="
      position:fixed; left:0; right:0; bottom:0;
      display:flex; gap:10px; padding:10px;
      background:#fff; border-top:1px solid #ddd;
      font-family:system-ui, -apple-system, Segoe UI, Roboto, Arial;
      z-index:9999;
    ">
      <a href="{sms_link}" style="flex:1; text-align:center; padding:10px; border:1px solid #ddd; border-radius:12px; text-decoration:none; color:#111;">
        <div style="font-weight:700;">Text Office</div>
        <div style="font-size:12px; color:#555;">{phone_display}</div>
      </a>

      <a href="{tel_link}" style="flex:1; text-align:center; padding:10px; border:1px solid #ddd; border-radius:12px; text-decoration:none; color:#111;">
        <div style="font-weight:700;">Call Office</div>
        <div style="font-size:12px; color:#555;">{phone_display}</div>
      </a>

      <a href="{vcard_link}" style="flex:1; text-align:center; padding:10px; border:1px solid #ddd; border-radius:12px; text-decoration:none; color:#111;">
        <div style="font-weight:700;">Save</div>
        <div style="font-size:12px; color:#555;">Add to contacts</div>
      </a>
    </div>

    <div style="height:95px;"></div>
    """


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
        raise HTTPException(status_code=404, detail="Tech not found")

    if tech["status"] != "active":
        sms_body = "Hi — I’m trying to verify a technician at my door. Can you confirm who’s assigned today?"
        contact_bar = _contact_bar_html(company_code, phone_e164, phone_display, sms_body)

        body = f"""
        <h1 style="margin:0 0 8px 0;">Verify your appointment</h1>
        <p style="margin:0 0 12px 0; line-height:1.4;">
          For your safety, this verification link isn’t currently active.
          Please contact <b>{company['name']}</b> to confirm your scheduled service.
        </p>

        <div style="padding:12px; border:1px solid #eee; border-radius:12px;">
          <div style="font-weight:700; margin-bottom:6px;">Office</div>
          <div>{phone_display}</div>
          <div style="font-size:12px; color:#555; margin-top:6px;">
            Use the buttons below to text or call the office.
          </div>
        </div>

        {contact_bar}
        """
        return _html_page("Verify your appointment", body)

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

    lic_line = (
        f"<div style='margin-top:6px; color:#333;'><b>Lic #</b> {tech['license_number']}</div>"
        if tech["license_number"]
        else ""
    )

    if not in_review_mode:
        body = f"""
        <div style="font-size:12px; letter-spacing:0.08em; color:#666; text-transform:uppercase;">
          ServiceBadgeHQ • Proof at the door.
        </div>

        <h1 style="margin:10px 0 6px 0;">Meet your technician.</h1>

        <div style="padding:14px; border:1px solid #eee; border-radius:14px;">
          <div style="font-size:22px; font-weight:800;">{tech['name']}</div>
          <div style="font-size:14px; color:#444; margin-top:2px;">{tech['role']} • {company['name']}</div>
          {lic_line}
          <div style="margin-top:10px; line-height:1.4; color:#333;">
            This page lets you quickly verify who’s on site today and contact the office if needed.
          </div>
        </div>

        {contact_bar}
        """
        return _html_page(f"{tech['name']} — {company['name']}", body)

    cc = company_code.upper()
    slug = tech["slug"]

    body = f"""
    <div style="font-size:12px; letter-spacing:0.08em; color:#666; text-transform:uppercase;">
      ServiceBadgeHQ • Proof at the door.
    </div>

    <h1 style="margin:10px 0 6px 0;">Thanks for choosing {company['name']}.</h1>
    <p style="margin:0 0 12px 0; line-height:1.4;">
      If we earned it, a quick review helps a lot. It helps the next customer feel confident calling us.
    </p>

    <div style="padding:14px; border:1px solid #eee; border-radius:14px;">
      <div style="font-weight:800; margin-bottom:10px;">Rate your experience</div>
      <div style="display:flex; gap:8px; flex-wrap:wrap;">
        <a href="/t/{cc}/{slug}/rate?score=1" style="padding:10px 12px; border:1px solid #ddd; border-radius:10px; text-decoration:none; color:#111;">1</a>
        <a href="/t/{cc}/{slug}/rate?score=2" style="padding:10px 12px; border:1px solid #ddd; border-radius:10px; text-decoration:none; color:#111;">2</a>
        <a href="/t/{cc}/{slug}/rate?score=3" style="padding:10px 12px; border:1px solid #ddd; border-radius:10px; text-decoration:none; color:#111;">3</a>
        <a href="/t/{cc}/{slug}/rate?score=4" style="padding:10px 12px; border:1px solid #ddd; border-radius:10px; text-decoration:none; color:#111;">4</a>
        <a href="/t/{cc}/{slug}/rate?score=5" style="padding:10px 12px; border:1px solid #ddd; border-radius:10px; text-decoration:none; color:#111;">5</a>
      </div>

      <div style="font-size:12px; color:#666; margin-top:10px;">
        4–5 stars will take you to Google. 1–3 stays private so we can fix it.
      </div>
    </div>

    {contact_bar}
    """
    return _html_page(f"Review — {company['name']}", body)


# -----------------------------
# PUBLIC: Rating + Feedback
# -----------------------------
@app.get("/t/{company_code}/{tech_slug}/rate", response_class=HTMLResponse)
def rate_experience(company_code: str, tech_slug: str, score: int, db: Session = Depends(get_db)):
    if score < 1 or score > 5:
        raise HTTPException(status_code=400, detail="Score must be 1-5")

    company = db.execute(
        text("SELECT id, name, code, google_review_url, phone_e164 FROM companies WHERE code=:code"),
        {"code": company_code.upper()},
    ).mappings().first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

    tech = db.execute(
        text("SELECT id, status, slug FROM techs WHERE company_id=:cid AND slug=:slug"),
        {"cid": company["id"], "slug": tech_slug.lower()},
    ).mappings().first()
    if not tech:
        raise HTTPException(status_code=404, detail="Tech not found")

    if tech["status"] != "active":
        raise HTTPException(status_code=400, detail="Technician not active")

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
    <div style="font-size:12px; letter-spacing:0.08em; color:#666; text-transform:uppercase;">
      ServiceBadgeHQ • Private feedback
    </div>

    <h1 style="margin:10px 0 10px 0;">Thanks — we hear you.</h1>
    <p style="margin:0 0 14px 0; line-height:1.4;">
      We’d rather fix it than fight about it. Tell us what happened and the office will follow up.
    </p>

    <form method="post" action="/t/{cc}/{slug}/feedback" style="margin-top:10px;">
      <input type="hidden" name="score" value="{score}" />
      <input type="hidden" name="rating_id" value="{rating_id}" />

      <label style="display:block; font-weight:700; margin-bottom:8px;">What went wrong?</label>
      <textarea name="message" rows="5" required
        style="width:100%; padding:10px; border:1px solid #ddd; border-radius:12px; font-family:inherit;"></textarea>

      <button type="submit"
        style="margin-top:12px; width:100%; padding:12px; border:0; border-radius:12px; background:#111; color:#fff; font-weight:800;">
        Send privately to the office
      </button>

      <p style="margin:10px 0 0 0; font-size:12px; color:#666;">
        This goes to the office privately — it does not post publicly.
      </p>
    </form>

    {contact_bar}
    """
    return _html_page("We hear you", body)


@app.post("/t/{company_code}/{tech_slug}/feedback", response_class=HTMLResponse)
def submit_feedback(
    company_code: str,
    tech_slug: str,
    score: int = Form(...),
    message: str = Form(...),
    rating_id: str = Form(None),
    db: Session = Depends(get_db),
):
    message = (message or "").strip()
    if not message:
        raise HTTPException(status_code=400, detail="Message required")

    company = db.execute(
        text("SELECT id, name, phone_e164 FROM companies WHERE code=:code"),
        {"code": company_code.upper()},
    ).mappings().first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

    tech = db.execute(
        text("SELECT id, status FROM techs WHERE company_id=:cid AND slug=:slug"),
        {"cid": company["id"], "slug": tech_slug.lower()},
    ).mappings().first()
    if not tech:
        raise HTTPException(status_code=404, detail="Tech not found")

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
    <div style="font-size:12px; letter-spacing:0.08em; color:#666; text-transform:uppercase;">
      ServiceBadgeHQ • Private feedback
    </div>

    <h1 style="margin:10px 0 10px 0;">Got it.</h1>
    <p style="margin:0 0 12px 0; line-height:1.4;">
      Thanks for letting us know. The office will follow up to make it right.
    </p>

    {contact_bar}
    """
    return _html_page("Received", body)


# -----------------------------
# Tech portal routes
# -----------------------------
@app.get("/login", response_class=HTMLResponse)
def login_page():
    body = """
    <h1 style="margin:0 0 10px 0;">Tech Login</h1>
    <p style="margin:0 0 14px 0; color:#444;">Enter your Company Code and 6-digit PIN.</p>

    <form method="post" action="/auth/pair">
      <label style="display:block; font-weight:700; margin-bottom:6px;">Company Code</label>
      <input name="company_code" required style="width:100%; padding:10px; border:1px solid #ddd; border-radius:12px;" />

      <label style="display:block; font-weight:700; margin:12px 0 6px 0;">PIN</label>
      <input name="pin" required inputmode="numeric" maxlength="6"
        style="width:100%; padding:10px; border:1px solid #ddd; border-radius:12px;" />

      <button type="submit" style="margin-top:14px; width:100%; padding:12px; border:0; border-radius:12px; background:#111; color:#fff; font-weight:800;">
        Pair Device
      </button>
    </form>
    """
    return _html_page("Tech Login", body)


@app.post("/auth/pair")
def auth_pair(
    request: Request,
    company_code: str = Form(...),
    pin: str = Form(...),
    db: Session = Depends(get_db),
):
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
    <div style="font-size:12px; letter-spacing:0.08em; color:#666; text-transform:uppercase;">
      ServiceBadgeHQ • Tech Portal
    </div>

    <h1 style="margin:10px 0 6px 0;">Hey, {tech['name']}.</h1>
    <p style="margin:0 0 14px 0; color:#444;">Your public link:</p>

    <div style="padding:12px; border:1px solid #eee; border-radius:12px; margin-bottom:14px;">
      <div style="font-weight:800;">{public_link}</div>
      <div style="font-size:12px; color:#666; margin-top:6px;">(This is the QR/NFC destination.)</div>
    </div>

    <h2 style="margin:0 0 8px 0; font-size:16px;">Share Templates</h2>
    <div style="padding:12px; border:1px solid #eee; border-radius:12px;">
      <div style="font-weight:700;">On my way</div>
      <div style="font-size:13px; color:#333; margin:6px 0 10px 0;">{msg_on_my_way}</div>

      <div style="font-weight:700;">Verification</div>
      <div style="font-size:13px; color:#333; margin:6px 0 10px 0;">{msg_verify}</div>

      <div style="font-weight:700;">After job</div>
      <div style="font-size:13px; color:#333; margin:6px 0 0 0;">{msg_after_job}</div>
    </div>

    <h2 style="margin:16px 0 8px 0; font-size:16px;">Visit Controls</h2>

    <form method="post" action="/visits/start" style="padding:12px; border:1px solid #eee; border-radius:12px; margin-bottom:12px;">
      <div style="font-weight:800; margin-bottom:8px;">Start Visit (optional)</div>

      <label style="display:block; font-weight:700; margin-bottom:6px;">Customer name (optional)</label>
      <input name="customer_name" style="width:100%; padding:10px; border:1px solid #ddd; border-radius:12px;" />

      <label style="display:block; font-weight:700; margin:12px 0 6px 0;">Customer phone (optional)</label>
      <input name="customer_phone" style="width:100%; padding:10px; border:1px solid #ddd; border-radius:12px;" />

      <button type="submit" style="margin-top:12px; width:100%; padding:12px; border:0; border-radius:12px; background:#111; color:#fff; font-weight:800;">
        Start Visit
      </button>
    </form>

    <form method="post" action="/visits/complete" style="padding:12px; border:1px solid #eee; border-radius:12px;">
      <div style="font-weight:800; margin-bottom:8px;">Complete Visit</div>
      <div style="font-size:13px; color:#444; line-height:1.4;">
        This flips your public page into <b>Review Mode</b> for {company['review_mode_hours']} hours.
      </div>
      <button type="submit" style="margin-top:12px; width:100%; padding:12px; border:0; border-radius:12px; background:#111; color:#fff; font-weight:800;">
        Complete Visit + Enable Review Mode
      </button>
    </form>

    <form method="post" action="/logout" style="margin-top:14px;">
      <button type="submit" style="width:100%; padding:12px; border:1px solid #ddd; border-radius:12px; background:#fff; color:#111; font-weight:800;">
        Logout
      </button>
    </form>
    """
    return _html_page("Tech Portal", body)


# -----------------------------
# Visits routes
# -----------------------------
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
    <h1 style="margin:0 0 10px 0;">Admin Login</h1>

    <form method="post" action="/admin/login">
      <label style="display:block; font-weight:700; margin-bottom:6px;">Email</label>
      <input name="email" required style="width:100%; padding:10px; border:1px solid #ddd; border-radius:12px;" />

      <label style="display:block; font-weight:700; margin:12px 0 6px 0;">Password</label>
      <input type="password" name="password" required style="width:100%; padding:10px; border:1px solid #ddd; border-radius:12px;" />

      <button type="submit" style="margin-top:14px; width:100%; padding:12px; border:0; border-radius:12px; background:#111; color:#fff; font-weight:800;">
        Sign in
      </button>
    </form>
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
    companies = db.execute(text("SELECT id, name, code FROM companies ORDER BY name ASC")).mappings().all()

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

    tech_list = ""
    for t in tech_rows:
        public_link = f"/t/{t['company_code']}/{t['slug']}"
        tech_list += f"""
          <tr>
            <td>{t['company_name']}</td>
            <td>{t['name']}</td>
            <td>{t['role']}</td>
            <td>{t['slug']}</td>
            <td>{t['status']}</td>
            <td><a href="{public_link}" target="_blank">Open</a></td>
            <td style="white-space:nowrap;">
              <form method="post" action="/admin/tech/{t['id']}/reset-pin" style="display:inline;">
                <input name="new_pin" placeholder="New PIN" maxlength="6" style="width:90px; padding:6px; border:1px solid #ddd; border-radius:10px;" required />
                <button style="padding:6px 10px; border:1px solid #ddd; border-radius:10px; background:#fff;">Reset PIN</button>
              </form>

              <form method="post" action="/admin/tech/{t['id']}/revoke-sessions" style="display:inline;">
                <button style="padding:6px 10px; border:1px solid #ddd; border-radius:10px; background:#fff;">Revoke Sessions</button>
              </form>

              <form method="post" action="/admin/tech/{t['id']}/toggle" style="display:inline;">
                <button style="padding:6px 10px; border:1px solid #ddd; border-radius:10px; background:#fff;">
                  Toggle Active
                </button>
              </form>
            </td>
          </tr>
        """

    body = f"""
    <div style="display:flex; justify-content:space-between; align-items:center;">
      <h1 style="margin:0;">Admin</h1>
      <div style="display:flex; gap:10px;">
        <a href="/admin/feedback" style="padding:10px 12px; border:1px solid #ddd; border-radius:12px; background:#fff; font-weight:800; text-decoration:none; color:#111;">Feedback Inbox</a>
        <form method="post" action="/admin/logout" style="margin:0;">
          <button style="padding:10px 12px; border:1px solid #ddd; border-radius:12px; background:#fff; font-weight:800;">Logout</button>
        </form>
      </div>
    </div>

    <h2 style="margin:16px 0 8px 0; font-size:16px;">Create Tech</h2>
    <form method="post" action="/admin/tech/create" style="padding:12px; border:1px solid #eee; border-radius:12px;">
      <label style="display:block; font-weight:700; margin-bottom:6px;">Company</label>
      <select name="company_id" required style="width:100%; padding:10px; border:1px solid #ddd; border-radius:12px;">
        {company_options}
      </select>

      <label style="display:block; font-weight:700; margin:12px 0 6px 0;">Tech name</label>
      <input name="name" required style="width:100%; padding:10px; border:1px solid #ddd; border-radius:12px;" />

      <label style="display:block; font-weight:700; margin:12px 0 6px 0;">Role</label>
      <input name="role" required placeholder="Technician" style="width:100%; padding:10px; border:1px solid #ddd; border-radius:12px;" />

      <label style="display:block; font-weight:700; margin:12px 0 6px 0;">Slug (URL)</label>
      <input name="slug" required placeholder="mike" style="width:100%; padding:10px; border:1px solid #ddd; border-radius:12px;" />

      <label style="display:block; font-weight:700; margin:12px 0 6px 0;">PIN (6 digits)</label>
      <input name="pin" required maxlength="6" inputmode="numeric" style="width:100%; padding:10px; border:1px solid #ddd; border-radius:12px;" />

      <label style="display:block; font-weight:700; margin:12px 0 6px 0;">Lic # (optional)</label>
      <input name="license_number" style="width:100%; padding:10px; border:1px solid #ddd; border-radius:12px;" />

      <button style="margin-top:12px; width:100%; padding:12px; border:0; border-radius:12px; background:#111; color:#fff; font-weight:800;">
        Create Tech
      </button>
    </form>

    <h2 style="margin:16px 0 8px 0; font-size:16px;">Techs</h2>
    <div style="overflow:auto; border:1px solid #eee; border-radius:12px;">
      <table style="width:100%; border-collapse:collapse; font-size:14px;">
        <thead>
          <tr style="background:#fafafa;">
            <th style="text-align:left; padding:10px; border-bottom:1px solid #eee;">Company</th>
            <th style="text-align:left; padding:10px; border-bottom:1px solid #eee;">Name</th>
            <th style="text-align:left; padding:10px; border-bottom:1px solid #eee;">Role</th>
            <th style="text-align:left; padding:10px; border-bottom:1px solid #eee;">Slug</th>
            <th style="text-align:left; padding:10px; border-bottom:1px solid #eee;">Status</th>
            <th style="text-align:left; padding:10px; border-bottom:1px solid #eee;">Public</th>
            <th style="text-align:left; padding:10px; border-bottom:1px solid #eee;">Actions</th>
          </tr>
        </thead>
        <tbody>
          {tech_list}
        </tbody>
      </table>
    </div>
    """
    return _html_page("Admin", body)


@app.post("/admin/tech/create")
def admin_create_tech(
    request: Request,
    company_id: str = Form(...),
    name: str = Form(...),
    role: str = Form(...),
    slug: str = Form(...),
    pin: str = Form(...),
    license_number: str = Form(None),
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    slug_norm = slug.strip().lower().replace(" ", "-")
    pin_norm = (pin or "").strip()

    if len(pin_norm) < 4:
        raise HTTPException(status_code=400, detail="PIN too short")

    pin_hash = bcrypt.hash(pin_norm)

    db.execute(
        text(
            """
            INSERT INTO techs (company_id, name, role, slug, license_number, status, pin_hash)
            VALUES (:company_id, :name, :role, :slug, :license_number, 'active', :pin_hash)
            """
        ),
        {
            "company_id": company_id,
            "name": name.strip(),
            "role": role.strip(),
            "slug": slug_norm,
            "license_number": (license_number or "").strip() or None,
            "pin_hash": pin_hash,
        },
    )
    db.commit()

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
        raise HTTPException(status_code=404, detail="Tech not found")

    new_status = "disabled" if tech["status"] == "active" else "active"
    db.execute(text("UPDATE techs SET status=:s WHERE id=:id"), {"s": new_status, "id": tech_id})
    db.commit()
    return RedirectResponse(url="/admin", status_code=302)


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
            return "<p style='color:#666; margin:0;'>None.</p>"

        out = "<div style='display:flex; flex-direction:column; gap:12px;'>"
        for r in rows:
            public_link = f"/t/{r['company_code']}/{r['tech_slug']}"
            if mode == "open":
                action = f"""
                <form method="post" action="/admin/feedback/{r['id']}/resolve" style="margin:0;">
                  <button style="padding:10px 12px; border:1px solid #ddd; border-radius:12px; background:#fff; font-weight:800;">
                    Mark Resolved
                  </button>
                </form>
                """
            else:
                action = f"""
                <form method="post" action="/admin/feedback/{r['id']}/reopen" style="margin:0;">
                  <button style="padding:10px 12px; border:1px solid #ddd; border-radius:12px; background:#fff; font-weight:800;">
                    Reopen
                  </button>
                </form>
                """

            out += f"""
            <div style="border:1px solid #eee; border-radius:14px; padding:12px;">
              <div style="display:flex; justify-content:space-between; gap:10px; align-items:flex-start;">
                <div>
                  <div style="font-weight:800;">{esc(r['company_name'])} • {esc(r['tech_name'])} • {r['score']}/5</div>
                  <div style="font-size:12px; color:#666; margin-top:2px;">{r['created_at']}</div>
                  <div style="margin-top:10px; line-height:1.4;">{esc(r['message'])}</div>
                  <div style="margin-top:10px; font-size:12px;">
                    <a href="{public_link}" target="_blank">Open public page</a>
                  </div>
                </div>
                <div style="display:flex; flex-direction:column; gap:8px; min-width:140px;">
                  {action}
                </div>
              </div>
            </div>
            """
        out += "</div>"
        return out

    body = f"""
    <div style="display:flex; justify-content:space-between; align-items:center; gap:10px;">
      <h1 style="margin:0;">Feedback Inbox</h1>
      <div style="display:flex; gap:10px;">
        <a href="/admin" style="padding:10px 12px; border:1px solid #ddd; border-radius:12px; background:#fff; font-weight:800; text-decoration:none; color:#111;">Admin</a>
        <form method="post" action="/admin/logout" style="margin:0;">
          <button style="padding:10px 12px; border:1px solid #ddd; border-radius:12px; background:#fff; font-weight:800;">Logout</button>
        </form>
      </div>
    </div>

    <h2 style="margin:16px 0 10px 0; font-size:16px;">Open</h2>
    {render_rows(open_rows, "open")}

    <h2 style="margin:18px 0 10px 0; font-size:16px;">Resolved</h2>
    {render_rows(resolved_rows, "resolved")}
    """
    return _html_page("Feedback Inbox", body)


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
