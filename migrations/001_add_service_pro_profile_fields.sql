-- Adds optional public profile + payment link fields for Service Pros.
-- Safe to re-run because each column uses IF NOT EXISTS.
ALTER TABLE techs
  ADD COLUMN IF NOT EXISTS bio_short text,
  ADD COLUMN IF NOT EXISTS venmo_url text,
  ADD COLUMN IF NOT EXISTS zelle_url text,
  ADD COLUMN IF NOT EXISTS paypal_url text,
  ADD COLUMN IF NOT EXISTS cashapp_url text,
  ADD COLUMN IF NOT EXISTS apple_pay_url text,
  ADD COLUMN IF NOT EXISTS google_pay_url text;
