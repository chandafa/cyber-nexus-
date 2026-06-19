-- NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
-- Skema D1 untuk server lisensi Nexus.
CREATE TABLE IF NOT EXISTS licenses (
  code          TEXT PRIMARY KEY,
  tier          TEXT NOT NULL DEFAULT 'pro',
  status        TEXT NOT NULL DEFAULT 'unused',   -- unused | redeemed | revoked
  device_id     TEXT,
  duration_days INTEGER NOT NULL DEFAULT 30,
  licensee      TEXT DEFAULT '',
  created_at    INTEGER,
  redeemed_at   INTEGER,
  expires_at    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_licenses_status ON licenses(status);
