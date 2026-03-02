# Contributing to ServiceBadgeHQ

## Principles
- Keep customer flow frictionless (QR/NFC should open instantly)
- Keep technician privacy intact (office-only contact)
- Keep code simple and readable (MVP first)

## Setup
1) Create venv: `python3 -m venv .venv && source .venv/bin/activate`
2) Install deps: `pip install -r requirements.txt`
3) Set env: `cp .env.example .env` then fill values
4) Run: `uvicorn app.main:app --host 127.0.0.1 --port 8000`

## Branching
- `main` is deployable
- Feature work in `feature/<name>`

## Pull requests
- Describe the change in plain language
- Include screenshots for UI changes
- No secrets (never commit `.env` or credentials)
