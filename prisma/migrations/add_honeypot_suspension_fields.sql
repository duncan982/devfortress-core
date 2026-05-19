-- Add suspendedReason and suspendedAt fields to Honeypot table
-- This migration adds support for honeypot suspension tracking

-- Add suspendedReason column
ALTER TABLE "Honeypot" ADD COLUMN IF NOT EXISTS "suspendedReason" TEXT;

-- Add suspendedAt column
ALTER TABLE "Honeypot" ADD COLUMN IF NOT EXISTS "suspendedAt" TIMESTAMP(3);

-- Add comment for documentation
COMMENT ON COLUMN "Honeypot"."suspendedReason" IS 'Reason why the honeypot was suspended';
COMMENT ON COLUMN "Honeypot"."suspendedAt" IS 'Timestamp when the honeypot was suspended';
