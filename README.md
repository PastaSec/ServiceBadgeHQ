# ServiceBadgeHQ

Tap-to-verify badges for service businesses: prove who’s at the door, contact the office, and route happy customers to Google reviews while keeping low ratings private for fast resolution.

## What it does (MVP)
- Public technician verification page (`/t/{company}/{tech}`)
  - Meet mode vs Review mode (time-based)
  - Office-only contact actions (call/text/save vCard)
- Review routing
  - 4–5 → Google review link
  - 1–3 → private feedback form stored in DB
- Tech portal
  - Pair device with Company Code + PIN
  - Start/complete visit (complete triggers review mode)
- Admin portal
  - Admin login + session
  - Create tech, reset PIN, revoke sessions, disable tech
  - Feedback inbox (Open + Resolved)
- PWA support
  - Manifest + icons + service worker
  - Installable on Android/iOS/Desktop

## Tech stack
- FastAPI + Uvicorn
- PostgreSQL
- Nginx reverse proxy
- systemd service
- PWA (manifest + SW)

## Local/dev setup
### 1) Create venv and install dependencies
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
