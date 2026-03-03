-- Adds optional company-level branding fields.
-- Safe to re-run because each column uses IF NOT EXISTS.
ALTER TABLE companies
  ADD COLUMN IF NOT EXISTS brand_logo_url text,
  ADD COLUMN IF NOT EXISTS brand_primary_color text,
  ADD COLUMN IF NOT EXISTS brand_accent_color text,
  ADD COLUMN IF NOT EXISTS brand_tagline text;
