-- =============================================================================
-- Migration: Add CL Audit Trail, Blocked IPs, and Webhook Deliveries tables
-- Date: 2026-04-08
-- Purpose: Closed-Loop MVP — Items #44, #45, #29-31 from CL todos
-- =============================================================================

-- CL Audit Trail table — records detect → action → confirm chain
CREATE TABLE IF NOT EXISTS "ClAuditTrail" (
    "id"              TEXT NOT NULL DEFAULT gen_random_uuid()::text,
    "projectId"       TEXT NOT NULL,
    "detectEventId"   TEXT NOT NULL,
    "action"          TEXT NOT NULL,
    "clMode"          TEXT NOT NULL,
    "authPhase"       TEXT,
    "ip"              TEXT,
    "userId"          TEXT,
    "confirmed"       BOOLEAN NOT NULL DEFAULT false,
    "confirmedAt"     TIMESTAMP(3),
    "latencyMs"       INTEGER,
    "success"         BOOLEAN,
    "failureReason"   TEXT,
    "metadata"        JSONB,
    "createdAt"       TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt"       TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ClAuditTrail_pkey" PRIMARY KEY ("id")
);

CREATE INDEX IF NOT EXISTS "ClAuditTrail_projectId_idx" ON "ClAuditTrail"("projectId");
CREATE INDEX IF NOT EXISTS "ClAuditTrail_detectEventId_idx" ON "ClAuditTrail"("detectEventId");
CREATE INDEX IF NOT EXISTS "ClAuditTrail_createdAt_idx" ON "ClAuditTrail"("createdAt");
CREATE INDEX IF NOT EXISTS "ClAuditTrail_confirmed_idx" ON "ClAuditTrail"("confirmed");
CREATE INDEX IF NOT EXISTS "ClAuditTrail_action_idx" ON "ClAuditTrail"("action");

ALTER TABLE "ClAuditTrail" ADD CONSTRAINT "ClAuditTrail_projectId_fkey"
    FOREIGN KEY ("projectId") REFERENCES "ApiProject"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- Blocked IPs table — persistent IP blocklist with composite scoring
CREATE TABLE IF NOT EXISTS "BlockedIp" (
    "id"             TEXT NOT NULL DEFAULT gen_random_uuid()::text,
    "projectId"      TEXT NOT NULL,
    "ip"             TEXT NOT NULL,
    "compositeScore" DOUBLE PRECISION,
    "abuseIpDbScore" DOUBLE PRECISION,
    "dfSignalScore"  DOUBLE PRECISION,
    "source"         TEXT NOT NULL DEFAULT 'auto',
    "reason"         TEXT,
    "blockedAt"      TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt"      TIMESTAMP(3),
    "unblockedAt"    TIMESTAMP(3),
    "metadata"       JSONB,
    "createdAt"      TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt"      TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BlockedIp_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "BlockedIp_projectId_ip_key" ON "BlockedIp"("projectId", "ip");
CREATE INDEX IF NOT EXISTS "BlockedIp_projectId_idx" ON "BlockedIp"("projectId");
CREATE INDEX IF NOT EXISTS "BlockedIp_ip_idx" ON "BlockedIp"("ip");
CREATE INDEX IF NOT EXISTS "BlockedIp_blockedAt_idx" ON "BlockedIp"("blockedAt");
CREATE INDEX IF NOT EXISTS "BlockedIp_expiresAt_idx" ON "BlockedIp"("expiresAt");

ALTER TABLE "BlockedIp" ADD CONSTRAINT "BlockedIp_projectId_fkey"
    FOREIGN KEY ("projectId") REFERENCES "ApiProject"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- Webhook Deliveries table — outbound webhook tracking
CREATE TABLE IF NOT EXISTS "WebhookDelivery" (
    "id"            TEXT NOT NULL DEFAULT gen_random_uuid()::text,
    "projectId"     TEXT NOT NULL,
    "eventType"     TEXT NOT NULL,
    "targetUrl"     TEXT NOT NULL,
    "payload"       JSONB NOT NULL,
    "hmacSignature" TEXT,
    "httpStatus"    INTEGER,
    "responseBody"  TEXT,
    "success"       BOOLEAN NOT NULL DEFAULT false,
    "attempt"       INTEGER NOT NULL DEFAULT 1,
    "maxAttempts"   INTEGER NOT NULL DEFAULT 3,
    "nextRetryAt"   TIMESTAMP(3),
    "error"         TEXT,
    "deliveredAt"   TIMESTAMP(3),
    "createdAt"     TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "WebhookDelivery_pkey" PRIMARY KEY ("id")
);

CREATE INDEX IF NOT EXISTS "WebhookDelivery_projectId_idx" ON "WebhookDelivery"("projectId");
CREATE INDEX IF NOT EXISTS "WebhookDelivery_success_idx" ON "WebhookDelivery"("success");
CREATE INDEX IF NOT EXISTS "WebhookDelivery_createdAt_idx" ON "WebhookDelivery"("createdAt");
CREATE INDEX IF NOT EXISTS "WebhookDelivery_nextRetryAt_idx" ON "WebhookDelivery"("nextRetryAt");

ALTER TABLE "WebhookDelivery" ADD CONSTRAINT "WebhookDelivery_projectId_fkey"
    FOREIGN KEY ("projectId") REFERENCES "ApiProject"("id") ON DELETE CASCADE ON UPDATE CASCADE;
