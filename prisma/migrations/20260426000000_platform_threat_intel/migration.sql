
CREATE TABLE IF NOT EXISTS platform_threat_intel (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  indicator_type TEXT NOT NULL,
  indicator_value TEXT NOT NULL,
  severity TEXT NOT NULL,
  customer_count INTEGER DEFAULT 1,
  last_seen TIMESTAMPTZ DEFAULT NOW(),
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_threat_intel_indicator ON platform_threat_intel(indicator_type, indicator_value);
