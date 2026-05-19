-- CreateEnum
CREATE TYPE "BetaUserRole" AS ENUM ('TESTER', 'LEAD_TESTER', 'OBSERVER');

-- CreateEnum
CREATE TYPE "BetaUserStatus" AS ENUM ('INVITED', 'ACTIVE', 'INACTIVE', 'COMPLETED');

-- CreateEnum
CREATE TYPE "TestScenarioCategory" AS ENUM ('API_GENERATION', 'SECURITY_SCAN', 'DEPLOYMENT', 'MONITORING', 'GENERAL');

-- CreateEnum
CREATE TYPE "TestScenarioPriority" AS ENUM ('HIGH', 'MEDIUM', 'LOW');

-- CreateEnum
CREATE TYPE "TestScenarioStatus" AS ENUM ('DRAFT', 'ACTIVE', 'COMPLETED', 'DEPRECATED');

-- CreateEnum
CREATE TYPE "FeedbackType" AS ENUM ('BUG', 'FEATURE_REQUEST', 'USABILITY', 'PERFORMANCE', 'GENERAL');

-- CreateEnum
CREATE TYPE "FeedbackSeverity" AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW');

-- CreateEnum
CREATE TYPE "FeedbackStatus" AS ENUM ('NEW', 'TRIAGED', 'IN_PROGRESS', 'RESOLVED', 'WONT_FIX');

-- CreateEnum
CREATE TYPE "MonitorStatus" AS ENUM ('ACTIVE', 'PAUSED', 'DISABLED');

-- CreateEnum
CREATE TYPE "MonitorFrequency" AS ENUM ('ONE_MINUTE', 'FIVE_MINUTES', 'FIFTEEN_MINUTES', 'THIRTY_MINUTES', 'ONE_HOUR');

-- CreateEnum
CREATE TYPE "IncidentSeverity" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "IncidentStatus" AS ENUM ('OPEN', 'ACKNOWLEDGED', 'RESOLVED');

-- CreateEnum
CREATE TYPE "SecretType" AS ENUM ('API_KEY', 'ACCESS_TOKEN', 'DATABASE_PASSWORD', 'WEBHOOK_SECRET', 'ENCRYPTION_KEY');

-- CreateEnum
CREATE TYPE "SecretStatus" AS ENUM ('ACTIVE', 'ROTATING', 'DEPRECATED', 'REVOKED');

-- CreateEnum
CREATE TYPE "RotationStrategy" AS ENUM ('MANUAL', 'SCHEDULED', 'ON_DEMAND', 'EMERGENCY');

-- CreateEnum
CREATE TYPE "QuoteStatus" AS ENUM ('PENDING', 'SENT', 'ACCEPTED', 'REJECTED', 'EXPIRED');

-- CreateEnum
CREATE TYPE "ArticleCategory" AS ENUM ('GETTING_STARTED', 'API_GENERATION', 'SECURITY', 'HONEYPOTS', 'MONITORING', 'BILLING', 'TROUBLESHOOTING', 'TEAMS', 'INTEGRATIONS');

-- CreateEnum
CREATE TYPE "ArticleAudience" AS ENUM ('ALL', 'DEVELOPER', 'ADMIN', 'USER');

-- CreateEnum
CREATE TYPE "ConsentType" AS ENUM ('NECESSARY', 'ANALYTICS', 'MARKETING', 'PREFERENCES');

-- CreateEnum
CREATE TYPE "DataRequestType" AS ENUM ('ACCESS', 'DELETION', 'PORTABILITY', 'RECTIFICATION', 'RESTRICTION', 'OBJECTION');

-- CreateEnum
CREATE TYPE "RequestStatus" AS ENUM ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'REJECTED');

-- CreateEnum
CREATE TYPE "ChatbotConversationStatus" AS ENUM ('ACTIVE', 'RESOLVED', 'ESCALATED', 'CLOSED');

-- CreateEnum
CREATE TYPE "ChatbotMessageRole" AS ENUM ('USER', 'ASSISTANT', 'SYSTEM');

-- CreateEnum
CREATE TYPE "TicketStatus" AS ENUM ('OPEN', 'IN_PROGRESS', 'AWAITING_RESPONSE', 'RESOLVED', 'CLOSED');

-- CreateEnum
CREATE TYPE "TicketPriority" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "TicketSource" AS ENUM ('EMAIL', 'CHATBOT', 'MANUAL', 'API', 'PHONE');

-- AlterEnum
ALTER TYPE "HoneypotStatus" ADD VALUE 'SUSPENDED';

-- AlterTable
ALTER TABLE "Honeypot" ADD COLUMN     "suspendedAt" TIMESTAMP(3),
ADD COLUMN     "suspendedReason" TEXT;

-- CreateTable
CREATE TABLE "HoneypotTraffic" (
    "id" TEXT NOT NULL,
    "honeypotId" TEXT NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "ip" TEXT NOT NULL,
    "method" TEXT NOT NULL,
    "path" TEXT NOT NULL,
    "userAgent" TEXT,
    "headers" JSONB,
    "body" JSONB,
    "statusCode" INTEGER,
    "threatsDetected" INTEGER NOT NULL DEFAULT 0,
    "threatDetails" JSONB,

    CONSTRAINT "HoneypotTraffic_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "HoneypotAlert" (
    "id" TEXT NOT NULL,
    "honeypotId" TEXT NOT NULL,
    "severity" "ThreatSeverity" NOT NULL DEFAULT 'MEDIUM',
    "type" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "threats" JSONB NOT NULL,
    "recommendation" TEXT NOT NULL,
    "ip" TEXT NOT NULL,
    "path" TEXT NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "autoBlocked" BOOLEAN NOT NULL DEFAULT false,
    "resolved" BOOLEAN NOT NULL DEFAULT false,
    "resolvedAt" TIMESTAMP(3),
    "resolution" TEXT,

    CONSTRAINT "HoneypotAlert_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AnomalyTrainingData" (
    "id" TEXT NOT NULL,
    "honeypotId" TEXT NOT NULL,
    "sourceIp" TEXT NOT NULL,
    "anomalyType" TEXT NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL,
    "severity" "ThreatSeverity" NOT NULL,
    "features" JSONB NOT NULL,
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "validated" BOOLEAN,
    "validatedAt" TIMESTAMP(3),
    "validatedBy" TEXT,

    CONSTRAINT "AnomalyTrainingData_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BetaUser" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "role" "BetaUserRole" NOT NULL DEFAULT 'TESTER',
    "status" "BetaUserStatus" NOT NULL DEFAULT 'INVITED',
    "invitedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "activatedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "testScenarios" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "feedbackCount" INTEGER NOT NULL DEFAULT 0,
    "metadata" JSONB,

    CONSTRAINT "BetaUser_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TestScenario" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "category" "TestScenarioCategory" NOT NULL,
    "priority" "TestScenarioPriority" NOT NULL,
    "steps" TEXT[],
    "expectedOutcome" TEXT NOT NULL,
    "status" "TestScenarioStatus" NOT NULL DEFAULT 'DRAFT',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "TestScenario_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BetaFeedback" (
    "id" TEXT NOT NULL,
    "betaUserId" TEXT NOT NULL,
    "scenarioId" TEXT,
    "type" "FeedbackType" NOT NULL,
    "severity" "FeedbackSeverity" NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "steps" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "expectedBehavior" TEXT,
    "actualBehavior" TEXT,
    "screenshots" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "status" "FeedbackStatus" NOT NULL DEFAULT 'NEW',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "resolvedAt" TIMESTAMP(3),
    "metadata" JSONB,

    CONSTRAINT "BetaFeedback_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "APIMonitor" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "teamId" TEXT,
    "name" TEXT NOT NULL,
    "endpoint" TEXT NOT NULL,
    "method" TEXT NOT NULL DEFAULT 'GET',
    "headers" JSONB NOT NULL DEFAULT '{}',
    "body" TEXT,
    "expectedStatusCode" INTEGER NOT NULL DEFAULT 200,
    "expectedResponseTime" INTEGER NOT NULL DEFAULT 5000,
    "frequency" "MonitorFrequency" NOT NULL DEFAULT 'FIVE_MINUTES',
    "status" "MonitorStatus" NOT NULL DEFAULT 'ACTIVE',
    "alertEmail" TEXT,
    "lastCheckedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "APIMonitor_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MonitorCheck" (
    "id" TEXT NOT NULL,
    "monitorId" TEXT NOT NULL,
    "statusCode" INTEGER NOT NULL,
    "responseTime" INTEGER NOT NULL,
    "success" BOOLEAN NOT NULL,
    "error" TEXT,
    "checkedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "MonitorCheck_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MonitorIncident" (
    "id" TEXT NOT NULL,
    "monitorId" TEXT NOT NULL,
    "severity" "IncidentSeverity" NOT NULL,
    "status" "IncidentStatus" NOT NULL DEFAULT 'OPEN',
    "message" TEXT NOT NULL,
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastOccurredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "resolvedAt" TIMESTAMP(3),

    CONSTRAINT "MonitorIncident_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Secret" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "teamId" TEXT,
    "name" TEXT NOT NULL,
    "type" "SecretType" NOT NULL,
    "value" TEXT NOT NULL,
    "status" "SecretStatus" NOT NULL DEFAULT 'ACTIVE',
    "lastRotatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "nextRotationAt" TIMESTAMP(3),
    "rotationIntervalDays" INTEGER NOT NULL DEFAULT 90,
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Secret_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecretRotationLog" (
    "id" TEXT NOT NULL,
    "secretId" TEXT NOT NULL,
    "strategy" "RotationStrategy" NOT NULL,
    "previousValue" TEXT NOT NULL,
    "newValue" TEXT NOT NULL,
    "rotatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3),

    CONSTRAINT "SecretRotationLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EnterpriseQuote" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "companyName" TEXT NOT NULL,
    "contactName" TEXT NOT NULL,
    "contactEmail" TEXT NOT NULL,
    "teamSize" INTEGER NOT NULL,
    "expectedAPIs" INTEGER NOT NULL,
    "expectedEventsPerMonth" INTEGER NOT NULL,
    "requiresSupport" BOOLEAN NOT NULL DEFAULT false,
    "requiresSLA" BOOLEAN NOT NULL DEFAULT false,
    "requiresCustomIntegration" BOOLEAN NOT NULL DEFAULT false,
    "additionalNotes" TEXT,
    "breakdown" JSONB NOT NULL,
    "status" "QuoteStatus" NOT NULL DEFAULT 'PENDING',
    "validUntil" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EnterpriseQuote_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "HelpArticle" (
    "id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "category" "ArticleCategory" NOT NULL,
    "audience" "ArticleAudience" NOT NULL DEFAULT 'ALL',
    "tags" TEXT[],
    "published" BOOLEAN NOT NULL DEFAULT true,
    "viewCount" INTEGER NOT NULL DEFAULT 0,
    "helpful" INTEGER NOT NULL DEFAULT 0,
    "notHelpful" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "HelpArticle_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "HelpFAQ" (
    "id" TEXT NOT NULL,
    "question" TEXT NOT NULL,
    "answer" TEXT NOT NULL,
    "category" "ArticleCategory" NOT NULL,
    "order" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "HelpFAQ_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserConsent" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "necessary" BOOLEAN NOT NULL DEFAULT true,
    "analytics" BOOLEAN NOT NULL DEFAULT false,
    "marketing" BOOLEAN NOT NULL DEFAULT false,
    "preferences" BOOLEAN NOT NULL DEFAULT false,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "consentedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "UserConsent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DataRequest" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "type" "DataRequestType" NOT NULL,
    "status" "RequestStatus" NOT NULL DEFAULT 'PENDING',
    "requestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),
    "notes" TEXT,

    CONSTRAINT "DataRequest_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserOnboarding" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "currentStep" INTEGER NOT NULL DEFAULT 1,
    "completedSteps" JSONB NOT NULL DEFAULT '[]',
    "skipped" BOOLEAN NOT NULL DEFAULT false,
    "completedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "UserOnboarding_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserMFA" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "secret" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "backupCodes" TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "UserMFA_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserSession" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "accessToken" TEXT NOT NULL,
    "refreshToken" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "refreshExpiresAt" TIMESTAMP(3) NOT NULL,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "lastActivity" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "mfaVerified" BOOLEAN NOT NULL DEFAULT false,
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "UserSession_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecurityScan" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "targetUrl" TEXT NOT NULL,
    "scanType" TEXT NOT NULL,
    "startTime" TIMESTAMP(3) NOT NULL,
    "endTime" TIMESTAMP(3) NOT NULL,
    "duration" INTEGER NOT NULL,
    "highAlerts" INTEGER NOT NULL DEFAULT 0,
    "mediumAlerts" INTEGER NOT NULL DEFAULT 0,
    "lowAlerts" INTEGER NOT NULL DEFAULT 0,
    "infoAlerts" INTEGER NOT NULL DEFAULT 0,
    "alerts" JSONB NOT NULL,
    "reportPath" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SecurityScan_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Incident" (
    "id" TEXT NOT NULL,
    "honeypotId" TEXT NOT NULL,
    "sourceIp" TEXT NOT NULL,
    "severity" "ThreatSeverity" NOT NULL,
    "type" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "responded" BOOLEAN NOT NULL DEFAULT false,
    "responseActions" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "resolvedAt" TIMESTAMP(3),
    "resolution" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Incident_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ChatbotConversation" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "sessionId" TEXT NOT NULL,
    "status" "ChatbotConversationStatus" NOT NULL DEFAULT 'ACTIVE',
    "topic" TEXT,
    "escalatedAt" TIMESTAMP(3),
    "escalatedReason" TEXT,
    "resolvedAt" TIMESTAMP(3),
    "satisfaction" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ChatbotConversation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ChatbotMessage" (
    "id" TEXT NOT NULL,
    "conversationId" TEXT NOT NULL,
    "role" "ChatbotMessageRole" NOT NULL,
    "content" TEXT NOT NULL,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ChatbotMessage_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SupportTicket" (
    "id" TEXT NOT NULL,
    "ticketNumber" TEXT NOT NULL,
    "userId" TEXT,
    "assignedToId" TEXT,
    "subject" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "status" "TicketStatus" NOT NULL DEFAULT 'OPEN',
    "priority" "TicketPriority" NOT NULL DEFAULT 'MEDIUM',
    "source" "TicketSource" NOT NULL DEFAULT 'MANUAL',
    "category" TEXT,
    "tags" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "externalId" TEXT,
    "externalUrl" TEXT,
    "conversationId" TEXT,
    "firstResponseAt" TIMESTAMP(3),
    "resolvedAt" TIMESTAMP(3),
    "closedAt" TIMESTAMP(3),
    "responseTime" INTEGER,
    "resolutionTime" INTEGER,
    "satisfaction" INTEGER,
    "satisfactionNote" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SupportTicket_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TicketMessage" (
    "id" TEXT NOT NULL,
    "ticketId" TEXT NOT NULL,
    "authorId" TEXT,
    "content" TEXT NOT NULL,
    "isInternal" BOOLEAN NOT NULL DEFAULT false,
    "isAutomated" BOOLEAN NOT NULL DEFAULT false,
    "attachments" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "TicketMessage_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "HoneypotTraffic_honeypotId_timestamp_idx" ON "HoneypotTraffic"("honeypotId", "timestamp");

-- CreateIndex
CREATE INDEX "HoneypotTraffic_ip_idx" ON "HoneypotTraffic"("ip");

-- CreateIndex
CREATE INDEX "HoneypotAlert_honeypotId_resolved_idx" ON "HoneypotAlert"("honeypotId", "resolved");

-- CreateIndex
CREATE INDEX "HoneypotAlert_severity_idx" ON "HoneypotAlert"("severity");

-- CreateIndex
CREATE INDEX "HoneypotAlert_timestamp_idx" ON "HoneypotAlert"("timestamp");

-- CreateIndex
CREATE INDEX "BetaUser_userId_idx" ON "BetaUser"("userId");

-- CreateIndex
CREATE INDEX "BetaUser_status_idx" ON "BetaUser"("status");

-- CreateIndex
CREATE INDEX "TestScenario_category_idx" ON "TestScenario"("category");

-- CreateIndex
CREATE INDEX "TestScenario_priority_idx" ON "TestScenario"("priority");

-- CreateIndex
CREATE INDEX "TestScenario_status_idx" ON "TestScenario"("status");

-- CreateIndex
CREATE INDEX "BetaFeedback_betaUserId_idx" ON "BetaFeedback"("betaUserId");

-- CreateIndex
CREATE INDEX "BetaFeedback_scenarioId_idx" ON "BetaFeedback"("scenarioId");

-- CreateIndex
CREATE INDEX "BetaFeedback_type_idx" ON "BetaFeedback"("type");

-- CreateIndex
CREATE INDEX "BetaFeedback_severity_idx" ON "BetaFeedback"("severity");

-- CreateIndex
CREATE INDEX "BetaFeedback_status_idx" ON "BetaFeedback"("status");

-- CreateIndex
CREATE INDEX "BetaFeedback_createdAt_idx" ON "BetaFeedback"("createdAt");

-- CreateIndex
CREATE INDEX "APIMonitor_userId_idx" ON "APIMonitor"("userId");

-- CreateIndex
CREATE INDEX "APIMonitor_teamId_idx" ON "APIMonitor"("teamId");

-- CreateIndex
CREATE INDEX "APIMonitor_status_idx" ON "APIMonitor"("status");

-- CreateIndex
CREATE INDEX "APIMonitor_lastCheckedAt_idx" ON "APIMonitor"("lastCheckedAt");

-- CreateIndex
CREATE INDEX "MonitorCheck_monitorId_idx" ON "MonitorCheck"("monitorId");

-- CreateIndex
CREATE INDEX "MonitorCheck_checkedAt_idx" ON "MonitorCheck"("checkedAt");

-- CreateIndex
CREATE INDEX "MonitorCheck_success_idx" ON "MonitorCheck"("success");

-- CreateIndex
CREATE INDEX "MonitorIncident_monitorId_idx" ON "MonitorIncident"("monitorId");

-- CreateIndex
CREATE INDEX "MonitorIncident_severity_idx" ON "MonitorIncident"("severity");

-- CreateIndex
CREATE INDEX "MonitorIncident_status_idx" ON "MonitorIncident"("status");

-- CreateIndex
CREATE INDEX "MonitorIncident_detectedAt_idx" ON "MonitorIncident"("detectedAt");

-- CreateIndex
CREATE INDEX "Secret_userId_idx" ON "Secret"("userId");

-- CreateIndex
CREATE INDEX "Secret_teamId_idx" ON "Secret"("teamId");

-- CreateIndex
CREATE INDEX "Secret_status_idx" ON "Secret"("status");

-- CreateIndex
CREATE INDEX "Secret_nextRotationAt_idx" ON "Secret"("nextRotationAt");

-- CreateIndex
CREATE INDEX "SecretRotationLog_secretId_idx" ON "SecretRotationLog"("secretId");

-- CreateIndex
CREATE INDEX "SecretRotationLog_rotatedAt_idx" ON "SecretRotationLog"("rotatedAt");

-- CreateIndex
CREATE INDEX "EnterpriseQuote_userId_idx" ON "EnterpriseQuote"("userId");

-- CreateIndex
CREATE INDEX "EnterpriseQuote_contactEmail_idx" ON "EnterpriseQuote"("contactEmail");

-- CreateIndex
CREATE INDEX "EnterpriseQuote_status_idx" ON "EnterpriseQuote"("status");

-- CreateIndex
CREATE INDEX "EnterpriseQuote_createdAt_idx" ON "EnterpriseQuote"("createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "HelpArticle_slug_key" ON "HelpArticle"("slug");

-- CreateIndex
CREATE INDEX "HelpArticle_category_idx" ON "HelpArticle"("category");

-- CreateIndex
CREATE INDEX "HelpArticle_audience_idx" ON "HelpArticle"("audience");

-- CreateIndex
CREATE INDEX "HelpArticle_published_idx" ON "HelpArticle"("published");

-- CreateIndex
CREATE INDEX "HelpArticle_slug_idx" ON "HelpArticle"("slug");

-- CreateIndex
CREATE INDEX "HelpFAQ_category_idx" ON "HelpFAQ"("category");

-- CreateIndex
CREATE INDEX "HelpFAQ_order_idx" ON "HelpFAQ"("order");

-- CreateIndex
CREATE INDEX "UserConsent_userId_idx" ON "UserConsent"("userId");

-- CreateIndex
CREATE INDEX "UserConsent_consentedAt_idx" ON "UserConsent"("consentedAt");

-- CreateIndex
CREATE INDEX "DataRequest_userId_idx" ON "DataRequest"("userId");

-- CreateIndex
CREATE INDEX "DataRequest_status_idx" ON "DataRequest"("status");

-- CreateIndex
CREATE INDEX "DataRequest_requestedAt_idx" ON "DataRequest"("requestedAt");

-- CreateIndex
CREATE UNIQUE INDEX "UserOnboarding_userId_key" ON "UserOnboarding"("userId");

-- CreateIndex
CREATE INDEX "UserOnboarding_userId_idx" ON "UserOnboarding"("userId");

-- CreateIndex
CREATE INDEX "UserOnboarding_completedAt_idx" ON "UserOnboarding"("completedAt");

-- CreateIndex
CREATE UNIQUE INDEX "UserMFA_userId_key" ON "UserMFA"("userId");

-- CreateIndex
CREATE INDEX "UserMFA_userId_idx" ON "UserMFA"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "UserSession_accessToken_key" ON "UserSession"("accessToken");

-- CreateIndex
CREATE UNIQUE INDEX "UserSession_refreshToken_key" ON "UserSession"("refreshToken");

-- CreateIndex
CREATE INDEX "UserSession_userId_idx" ON "UserSession"("userId");

-- CreateIndex
CREATE INDEX "UserSession_accessToken_idx" ON "UserSession"("accessToken");

-- CreateIndex
CREATE INDEX "UserSession_refreshToken_idx" ON "UserSession"("refreshToken");

-- CreateIndex
CREATE INDEX "UserSession_expiresAt_idx" ON "UserSession"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "SecurityScan_scanId_key" ON "SecurityScan"("scanId");

-- CreateIndex
CREATE INDEX "SecurityScan_targetUrl_idx" ON "SecurityScan"("targetUrl");

-- CreateIndex
CREATE INDEX "SecurityScan_scanType_idx" ON "SecurityScan"("scanType");

-- CreateIndex
CREATE INDEX "SecurityScan_startTime_idx" ON "SecurityScan"("startTime");

-- CreateIndex
CREATE INDEX "Incident_honeypotId_idx" ON "Incident"("honeypotId");

-- CreateIndex
CREATE INDEX "Incident_severity_idx" ON "Incident"("severity");

-- CreateIndex
CREATE INDEX "Incident_detectedAt_idx" ON "Incident"("detectedAt");

-- CreateIndex
CREATE INDEX "Incident_responded_idx" ON "Incident"("responded");

-- CreateIndex
CREATE UNIQUE INDEX "ChatbotConversation_sessionId_key" ON "ChatbotConversation"("sessionId");

-- CreateIndex
CREATE INDEX "ChatbotConversation_userId_idx" ON "ChatbotConversation"("userId");

-- CreateIndex
CREATE INDEX "ChatbotConversation_sessionId_idx" ON "ChatbotConversation"("sessionId");

-- CreateIndex
CREATE INDEX "ChatbotConversation_status_idx" ON "ChatbotConversation"("status");

-- CreateIndex
CREATE INDEX "ChatbotConversation_createdAt_idx" ON "ChatbotConversation"("createdAt");

-- CreateIndex
CREATE INDEX "ChatbotMessage_conversationId_idx" ON "ChatbotMessage"("conversationId");

-- CreateIndex
CREATE INDEX "ChatbotMessage_createdAt_idx" ON "ChatbotMessage"("createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "SupportTicket_ticketNumber_key" ON "SupportTicket"("ticketNumber");

-- CreateIndex
CREATE INDEX "SupportTicket_userId_idx" ON "SupportTicket"("userId");

-- CreateIndex
CREATE INDEX "SupportTicket_assignedToId_idx" ON "SupportTicket"("assignedToId");

-- CreateIndex
CREATE INDEX "SupportTicket_status_idx" ON "SupportTicket"("status");

-- CreateIndex
CREATE INDEX "SupportTicket_priority_idx" ON "SupportTicket"("priority");

-- CreateIndex
CREATE INDEX "SupportTicket_source_idx" ON "SupportTicket"("source");

-- CreateIndex
CREATE INDEX "SupportTicket_category_idx" ON "SupportTicket"("category");

-- CreateIndex
CREATE INDEX "SupportTicket_createdAt_idx" ON "SupportTicket"("createdAt");

-- CreateIndex
CREATE INDEX "SupportTicket_ticketNumber_idx" ON "SupportTicket"("ticketNumber");

-- CreateIndex
CREATE INDEX "TicketMessage_ticketId_idx" ON "TicketMessage"("ticketId");

-- CreateIndex
CREATE INDEX "TicketMessage_authorId_idx" ON "TicketMessage"("authorId");

-- CreateIndex
CREATE INDEX "TicketMessage_createdAt_idx" ON "TicketMessage"("createdAt");

-- AddForeignKey
ALTER TABLE "HoneypotTraffic" ADD CONSTRAINT "HoneypotTraffic_honeypotId_fkey" FOREIGN KEY ("honeypotId") REFERENCES "Honeypot"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "HoneypotAlert" ADD CONSTRAINT "HoneypotAlert_honeypotId_fkey" FOREIGN KEY ("honeypotId") REFERENCES "Honeypot"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AnomalyTrainingData" ADD CONSTRAINT "AnomalyTrainingData_honeypotId_fkey" FOREIGN KEY ("honeypotId") REFERENCES "Honeypot"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BetaUser" ADD CONSTRAINT "BetaUser_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BetaFeedback" ADD CONSTRAINT "BetaFeedback_betaUserId_fkey" FOREIGN KEY ("betaUserId") REFERENCES "BetaUser"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BetaFeedback" ADD CONSTRAINT "BetaFeedback_scenarioId_fkey" FOREIGN KEY ("scenarioId") REFERENCES "TestScenario"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "APIMonitor" ADD CONSTRAINT "APIMonitor_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "APIMonitor" ADD CONSTRAINT "APIMonitor_teamId_fkey" FOREIGN KEY ("teamId") REFERENCES "Team"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MonitorCheck" ADD CONSTRAINT "MonitorCheck_monitorId_fkey" FOREIGN KEY ("monitorId") REFERENCES "APIMonitor"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MonitorIncident" ADD CONSTRAINT "MonitorIncident_monitorId_fkey" FOREIGN KEY ("monitorId") REFERENCES "APIMonitor"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Secret" ADD CONSTRAINT "Secret_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Secret" ADD CONSTRAINT "Secret_teamId_fkey" FOREIGN KEY ("teamId") REFERENCES "Team"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SecretRotationLog" ADD CONSTRAINT "SecretRotationLog_secretId_fkey" FOREIGN KEY ("secretId") REFERENCES "Secret"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EnterpriseQuote" ADD CONSTRAINT "EnterpriseQuote_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Incident" ADD CONSTRAINT "Incident_honeypotId_fkey" FOREIGN KEY ("honeypotId") REFERENCES "Honeypot"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ChatbotConversation" ADD CONSTRAINT "ChatbotConversation_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ChatbotMessage" ADD CONSTRAINT "ChatbotMessage_conversationId_fkey" FOREIGN KEY ("conversationId") REFERENCES "ChatbotConversation"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SupportTicket" ADD CONSTRAINT "SupportTicket_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SupportTicket" ADD CONSTRAINT "SupportTicket_assignedToId_fkey" FOREIGN KEY ("assignedToId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TicketMessage" ADD CONSTRAINT "TicketMessage_ticketId_fkey" FOREIGN KEY ("ticketId") REFERENCES "SupportTicket"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TicketMessage" ADD CONSTRAINT "TicketMessage_authorId_fkey" FOREIGN KEY ("authorId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
