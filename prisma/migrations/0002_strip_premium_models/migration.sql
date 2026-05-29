-- Strip premium and internal-only models from open-core schema
-- This migration removes all tables, types, indexes, and FKs introduced
-- by the 0001 baseline that are not appropriate for the open-core public repo.

-- ── Drop FK constraints first (referencing tables being dropped) ────────────

-- Honeypot FKs
ALTER TABLE IF EXISTS "HoneypotTestResult" DROP CONSTRAINT IF EXISTS "HoneypotTestResult_honeypotId_fkey";
ALTER TABLE IF EXISTS "HoneypotTestResult" DROP CONSTRAINT IF EXISTS "HoneypotTestResult_userId_fkey";
ALTER TABLE IF EXISTS "HoneypotTraffic" DROP CONSTRAINT IF EXISTS "HoneypotTraffic_honeypotId_fkey";
ALTER TABLE IF EXISTS "HoneypotAlert" DROP CONSTRAINT IF EXISTS "HoneypotAlert_honeypotId_fkey";
ALTER TABLE IF EXISTS "ThreatEvent" DROP CONSTRAINT IF EXISTS "ThreatEvent_honeypotId_fkey";
ALTER TABLE IF EXISTS "ThreatEvent" DROP CONSTRAINT IF EXISTS "ThreatEvent_apiProjectId_fkey";
ALTER TABLE IF EXISTS "AnomalyTrainingData" DROP CONSTRAINT IF EXISTS "AnomalyTrainingData_honeypotId_fkey";
ALTER TABLE IF EXISTS "Incident" DROP CONSTRAINT IF EXISTS "Incident_honeypotId_fkey";
ALTER TABLE IF EXISTS "Honeypot" DROP CONSTRAINT IF EXISTS "Honeypot_apiProjectId_fkey";
ALTER TABLE IF EXISTS "Honeypot" DROP CONSTRAINT IF EXISTS "Honeypot_consultingClientId_fkey";
ALTER TABLE IF EXISTS "Honeypot" DROP CONSTRAINT IF EXISTS "Honeypot_organizationId_fkey";
ALTER TABLE IF EXISTS "Honeypot" DROP CONSTRAINT IF EXISTS "Honeypot_ownerId_fkey";
ALTER TABLE IF EXISTS "Honeypot" DROP CONSTRAINT IF EXISTS "Honeypot_repositoryId_fkey";
ALTER TABLE IF EXISTS "Honeypot" DROP CONSTRAINT IF EXISTS "Honeypot_teamId_fkey";

-- ConsultingClient/Job FKs
ALTER TABLE IF EXISTS "ConsultingJob" DROP CONSTRAINT IF EXISTS "ConsultingJob_clientId_fkey";
ALTER TABLE IF EXISTS "ConsultingJob" DROP CONSTRAINT IF EXISTS "ConsultingJob_userId_fkey";
ALTER TABLE IF EXISTS "ConsultingClient" DROP CONSTRAINT IF EXISTS "ConsultingClient_createdById_fkey";
ALTER TABLE IF EXISTS "AuditReport" DROP CONSTRAINT IF EXISTS "AuditReport_clientId_fkey";
ALTER TABLE IF EXISTS "AuditReport" DROP CONSTRAINT IF EXISTS "AuditReport_jobId_fkey";
ALTER TABLE IF EXISTS "ScanSchedule" DROP CONSTRAINT IF EXISTS "ScanSchedule_clientId_fkey";
ALTER TABLE IF EXISTS "ScanSchedule" DROP CONSTRAINT IF EXISTS "ScanSchedule_userId_fkey";

-- Enterprise FKs
ALTER TABLE IF EXISTS "EnterpriseSSOSession" DROP CONSTRAINT IF EXISTS "EnterpriseSSOSession_configId_fkey";
ALTER TABLE IF EXISTS "EnterpriseCertificate" DROP CONSTRAINT IF EXISTS "EnterpriseCertificate_configId_fkey";
ALTER TABLE IF EXISTS "EnterpriseInvoice" DROP CONSTRAINT IF EXISTS "EnterpriseInvoice_contractId_fkey";

-- Flywheel/Credit/WebhookDelivery FKs
ALTER TABLE IF EXISTS "FlywheelInsight" DROP CONSTRAINT IF EXISTS "FlywheelInsight_apiProjectId_fkey";
ALTER TABLE IF EXISTS "FlywheelInsight" DROP CONSTRAINT IF EXISTS "FlywheelInsight_ownerId_fkey";
ALTER TABLE IF EXISTS "CreditTransaction" DROP CONSTRAINT IF EXISTS "CreditTransaction_apiProjectId_fkey";
ALTER TABLE IF EXISTS "CreditTransaction" DROP CONSTRAINT IF EXISTS "CreditTransaction_balanceId_fkey";
ALTER TABLE IF EXISTS "CreditTransaction" DROP CONSTRAINT IF EXISTS "CreditTransaction_organizationId_fkey";
ALTER TABLE IF EXISTS "CreditTransaction" DROP CONSTRAINT IF EXISTS "CreditTransaction_userId_fkey";
ALTER TABLE IF EXISTS "CreditBalance" DROP CONSTRAINT IF EXISTS "CreditBalance_organizationId_fkey";
ALTER TABLE IF EXISTS "CreditBalance" DROP CONSTRAINT IF EXISTS "CreditBalance_userId_fkey";
ALTER TABLE IF EXISTS "WebhookDelivery" DROP CONSTRAINT IF EXISTS "WebhookDelivery_projectId_fkey";
ALTER TABLE IF EXISTS "CredentialAlias" DROP CONSTRAINT IF EXISTS "CredentialAlias_projectId_fkey";
ALTER TABLE IF EXISTS "EnterpriseQuote" DROP CONSTRAINT IF EXISTS "EnterpriseQuote_userId_fkey";

-- ── Drop FK columns in kept tables that pointed to removed tables ────────────
ALTER TABLE IF EXISTS "AuditReport" DROP COLUMN IF EXISTS "clientId";
ALTER TABLE IF EXISTS "AuditReport" DROP COLUMN IF EXISTS "jobId";

-- ── Drop premium/internal tables ─────────────────────────────────────────────
DROP TABLE IF EXISTS "HoneypotTestResult";
DROP TABLE IF EXISTS "HoneypotTraffic";
DROP TABLE IF EXISTS "HoneypotAlert";
DROP TABLE IF EXISTS "ThreatEvent";
DROP TABLE IF EXISTS "AnomalyTrainingData";
DROP TABLE IF EXISTS "Incident";
DROP TABLE IF EXISTS "Honeypot";
DROP TABLE IF EXISTS "FlywheelInsight";
DROP TABLE IF EXISTS "CreditTransaction";
DROP TABLE IF EXISTS "CreditBalance";
DROP TABLE IF EXISTS "WebhookDelivery";
DROP TABLE IF EXISTS "CredentialAlias";
DROP TABLE IF EXISTS "EnterpriseSSOSession";
DROP TABLE IF EXISTS "EnterpriseSSOConfig";
DROP TABLE IF EXISTS "EnterpriseCertificate";
DROP TABLE IF EXISTS "EnterpriseMTLSConfig";
DROP TABLE IF EXISTS "EnterpriseSIEMConfig";
DROP TABLE IF EXISTS "EnterprisePlaybook";
DROP TABLE IF EXISTS "EnterpriseAccountLockHistory";
DROP TABLE IF EXISTS "EnterpriseAccountLock";
DROP TABLE IF EXISTS "EnterpriseUsagePeriod";
DROP TABLE IF EXISTS "EnterpriseInvoice";
DROP TABLE IF EXISTS "EnterpriseContract";
DROP TABLE IF EXISTS "EnterpriseOnboardingRecord";
DROP TABLE IF EXISTS "EnterpriseQuote";
DROP TABLE IF EXISTS "SecurityScan";
DROP TABLE IF EXISTS "ScanSchedule";
DROP TABLE IF EXISTS "ConsultingJob";
DROP TABLE IF EXISTS "ConsultingClient";
DROP TABLE IF EXISTS "BlogSchedule";

-- ── Drop premium/internal enum types ─────────────────────────────────────────
DROP TYPE IF EXISTS "HoneypotStatus";
DROP TYPE IF EXISTS "CreditTransactionType";
DROP TYPE IF EXISTS "InsightType";
DROP TYPE IF EXISTS "QuoteStatus";
DROP TYPE IF EXISTS "ConsultingJobType";
DROP TYPE IF EXISTS "ConsultingJobStatus";
DROP TYPE IF EXISTS "ScanFrequency";
DROP TYPE IF EXISTS "EnterpriseSSOProvider";
DROP TYPE IF EXISTS "EnterpriseSSOStatus";
DROP TYPE IF EXISTS "EnterpriseCertStatus";
DROP TYPE IF EXISTS "EnterpriseCertType";
DROP TYPE IF EXISTS "EnterpriseSIEMProvider";
DROP TYPE IF EXISTS "EnterpriseAccountLockStatus";
DROP TYPE IF EXISTS "EnterpriseContractStatus";
DROP TYPE IF EXISTS "EnterpriseInvoiceStatus";

-- ── Clean up enum values for kept enums ──────────────────────────────────────
-- Remove BLOG_SCHEDULE from NotificationType (BlogSchedule model is removed)
ALTER TYPE "NotificationType" RENAME TO "NotificationType_old";
CREATE TYPE "NotificationType" AS ENUM ('FEEDBACK', 'CHAT_ESCALATION', 'SYSTEM', 'SECURITY', 'BILLING', 'UPDATE');
ALTER TABLE "Notification" ALTER COLUMN "type" TYPE "NotificationType" USING "type"::text::"NotificationType";
DROP TYPE "NotificationType_old";
