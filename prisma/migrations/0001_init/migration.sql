-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateEnum
CREATE TYPE "RefundRequestType" AS ENUM ('DISCRETIONARY', 'STATUTORY');

-- CreateEnum
CREATE TYPE "RefundRequestStatus" AS ENUM ('PENDING_APPROVAL', 'APPROVED', 'REJECTED');

-- CreateEnum
CREATE TYPE "UserRole" AS ENUM ('OWNER', 'ADMIN', 'DEVELOPER', 'VIEWER');

-- CreateEnum
CREATE TYPE "TeamRole" AS ENUM ('OWNER', 'ADMIN', 'DEVELOPER', 'VIEWER');

-- CreateEnum
CREATE TYPE "InvitationStatus" AS ENUM ('PENDING', 'ACCEPTED', 'EXPIRED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "OrganizationRole" AS ENUM ('OWNER', 'ADMIN', 'MEMBER', 'VIEWER');

-- CreateEnum
CREATE TYPE "RepositoryProvider" AS ENUM ('GITHUB', 'GITLAB', 'BITBUCKET');

-- CreateEnum
CREATE TYPE "RepositoryStatus" AS ENUM ('PENDING', 'CONNECTED', 'DISCONNECTED');

-- CreateEnum
CREATE TYPE "HoneypotStatus" AS ENUM ('INACTIVE', 'DEPLOYING', 'DEPLOYED', 'ACTIVE', 'PAUSED', 'SUSPENDED', 'ERROR', 'DECOMMISSIONED');

-- CreateEnum
CREATE TYPE "SubscriptionPlan" AS ENUM ('STARTER', 'PRO', 'ENTERPRISE', 'TEAM', 'BUSINESS', 'ENTERPRISE_PLUS');

-- CreateEnum
CREATE TYPE "SubscriptionStatus" AS ENUM ('TRIALING', 'ACTIVE', 'PAST_DUE', 'CANCELED');

-- CreateEnum
CREATE TYPE "ThreatSeverity" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INFO');

-- CreateEnum
CREATE TYPE "CreditTransactionType" AS ENUM ('ALLOCATION', 'CONSUMPTION', 'PURCHASE', 'ADJUSTMENT', 'REFUND');

-- CreateEnum
CREATE TYPE "LogLevel" AS ENUM ('INFO', 'WARN', 'ERROR', 'DEBUG');

-- CreateEnum
CREATE TYPE "InsightType" AS ENUM ('VULNERABILITY_TREND', 'ATTACK_PATTERN', 'PERFORMANCE', 'POLICY_VIOLATION');

-- CreateEnum
CREATE TYPE "ExportStatus" AS ENUM ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED', 'EXPIRED');

-- CreateEnum
CREATE TYPE "NotificationType" AS ENUM ('FEEDBACK', 'CHAT_ESCALATION', 'SYSTEM', 'SECURITY', 'BILLING', 'UPDATE');

-- CreateEnum
CREATE TYPE "NotificationStatus" AS ENUM ('UNREAD', 'READ', 'DISMISSED');

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

-- CreateEnum
CREATE TYPE "AIProvider" AS ENUM ('NL_GPT4', 'ML_HF');

-- CreateEnum
CREATE TYPE "AITaskType" AS ENUM ('API_GENERATION', 'SECURITY_SCAN', 'THREAT_ANALYSIS', 'VULNERABILITY_DETECTION', 'CODE_REVIEW', 'COMPLIANCE_CHECK');

-- CreateEnum
CREATE TYPE "DeploymentApprovalStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED');

-- CreateEnum
CREATE TYPE "DeploymentEnvironment" AS ENUM ('PREVIEW', 'PRODUCTION');

-- CreateEnum
CREATE TYPE "UserFeedbackType" AS ENUM ('THUMBS_UP', 'THUMBS_DOWN', 'FEATURE_REQUEST', 'BUG_REPORT', 'GENERAL');

-- CreateEnum
CREATE TYPE "UserFeedbackStatus" AS ENUM ('NEW', 'REVIEWED', 'PLANNED', 'IN_PROGRESS', 'COMPLETED', 'WONT_FIX', 'DUPLICATE');

-- CreateEnum
CREATE TYPE "ConsultingJobType" AS ENUM ('AUDIT', 'URL_SCAN', 'BATCH_BUILD', 'BATCH_ANALYZE', 'HONEYPOT_DEPLOY');

-- CreateEnum
CREATE TYPE "ConsultingJobStatus" AS ENUM ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "AuditReportStatus" AS ENUM ('GENERATING', 'COMPLETED', 'FAILED');

-- CreateEnum
CREATE TYPE "ScanFrequency" AS ENUM ('DAILY', 'WEEKLY', 'MONTHLY');

-- CreateEnum
CREATE TYPE "EnterpriseSSOProvider" AS ENUM ('OKTA', 'AZURE_AD', 'GOOGLE_WORKSPACE', 'ONELOGIN', 'JUMPCLOUD', 'GENERIC_SAML');

-- CreateEnum
CREATE TYPE "EnterpriseSSOStatus" AS ENUM ('PENDING_SETUP', 'CONFIGURING', 'TESTING', 'ACTIVE', 'ERROR', 'DISABLED');

-- CreateEnum
CREATE TYPE "EnterpriseCertStatus" AS ENUM ('ACTIVE', 'PENDING', 'REVOKED', 'EXPIRED', 'ROTATING');

-- CreateEnum
CREATE TYPE "EnterpriseCertType" AS ENUM ('ROOT_CA', 'INTERMEDIATE_CA', 'CLIENT', 'SERVER');

-- CreateEnum
CREATE TYPE "EnterpriseSIEMProvider" AS ENUM ('SPLUNK', 'DATADOG', 'SENTINEL', 'GENERIC_WEBHOOK', 'GENERIC_SYSLOG');

-- CreateEnum
CREATE TYPE "EnterpriseAccountLockStatus" AS ENUM ('ACTIVE', 'LOCKED', 'TEMPORARILY_LOCKED', 'PENDING_REVIEW');

-- CreateEnum
CREATE TYPE "EnterpriseContractStatus" AS ENUM ('ACTIVE', 'PENDING', 'EXPIRED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "EnterpriseInvoiceStatus" AS ENUM ('DRAFT', 'SENT', 'PAID', 'OVERDUE', 'VOID');

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "name" TEXT,
    "image" TEXT,
    "emailVerified" TIMESTAMP(3),
    "role" "UserRole" NOT NULL DEFAULT 'VIEWER',
    "preferredFramework" TEXT,
    "threatsRetentionDays" INTEGER DEFAULT 90,
    "alertsRetentionDays" INTEGER DEFAULT 60,
    "logsRetentionDays" INTEGER DEFAULT 30,
    "exportBeforeDelete" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "lastLoginAt" TIMESTAMP(3),
    "textbookPurchaser" BOOLEAN NOT NULL DEFAULT false,
    "hasAcceptedTerms" BOOLEAN NOT NULL DEFAULT false,
    "hasAcceptedWarranties" BOOLEAN NOT NULL DEFAULT false,
    "hasAcceptedOversight" BOOLEAN NOT NULL DEFAULT false,
    "totpSecret" TEXT,
    "mfaEnabled" BOOLEAN NOT NULL DEFAULT false,
    "webauthnCredentials" JSONB,
    "acceptedTermsAt" TIMESTAMP(3),

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserApiKey" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "encryptedKey" TEXT NOT NULL,
    "iv" TEXT NOT NULL,
    "authTag" TEXT NOT NULL,
    "salt" TEXT NOT NULL,
    "maskedKey" TEXT NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "lastUsedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "UserApiKey_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Team" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "organizationId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "createdById" TEXT NOT NULL,

    CONSTRAINT "Team_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TeamMember" (
    "id" TEXT NOT NULL,
    "teamId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "role" "TeamRole" NOT NULL DEFAULT 'DEVELOPER',
    "joinedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "TeamMember_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TeamInvitation" (
    "id" TEXT NOT NULL,
    "teamId" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "role" "TeamRole" NOT NULL DEFAULT 'DEVELOPER',
    "invitedById" TEXT NOT NULL,
    "invitedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "acceptedAt" TIMESTAMP(3),
    "token" TEXT NOT NULL,
    "status" "InvitationStatus" NOT NULL DEFAULT 'PENDING',

    CONSTRAINT "TeamInvitation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Organization" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "ownerId" TEXT NOT NULL,

    CONSTRAINT "Organization_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OrganizationMember" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "role" "OrganizationRole" NOT NULL DEFAULT 'MEMBER',
    "joinedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "OrganizationMember_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ApiProject" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "description" TEXT,
    "framework" TEXT,
    "language" TEXT,
    "specification" JSONB,
    "metadata" JSONB,
    "rawResponse" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "createdById" TEXT NOT NULL,
    "teamId" TEXT,
    "organizationId" TEXT,
    "repositoryId" TEXT,
    "surveillanceApiKey" TEXT,
    "surveillanceKeyId" TEXT,
    "webhookSecret" TEXT,

    CONSTRAINT "ApiProject_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OperatorKey" (
    "id" TEXT NOT NULL,
    "operatorId" TEXT NOT NULL,
    "publicKeyPem" TEXT NOT NULL,
    "registeredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "OperatorKey_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Repository" (
    "id" TEXT NOT NULL,
    "provider" "RepositoryProvider" NOT NULL DEFAULT 'GITHUB',
    "externalId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "ownerLogin" TEXT NOT NULL,
    "installationId" TEXT,
    "defaultBranch" TEXT NOT NULL DEFAULT 'main',
    "status" "RepositoryStatus" NOT NULL DEFAULT 'PENDING',
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "ownerId" TEXT NOT NULL,
    "teamId" TEXT,
    "organizationId" TEXT,

    CONSTRAINT "Repository_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Honeypot" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "status" "HoneypotStatus" NOT NULL DEFAULT 'INACTIVE',
    "deploymentUrl" TEXT,
    "vercelProjectName" TEXT,
    "vercelProjectId" TEXT,
    "tier" "SubscriptionPlan" NOT NULL,
    "config" JSONB,
    "suspendedReason" TEXT,
    "suspendedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "ownerId" TEXT NOT NULL,
    "teamId" TEXT,
    "organizationId" TEXT,
    "apiProjectId" TEXT,
    "repositoryId" TEXT,
    "consultingClientId" TEXT,

    CONSTRAINT "Honeypot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "HoneypotTestResult" (
    "id" TEXT NOT NULL,
    "honeypotId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "attacksSent" INTEGER NOT NULL DEFAULT 0,
    "results" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "HoneypotTestResult_pkey" PRIMARY KEY ("id")
);

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
CREATE TABLE "ThreatEvent" (
    "id" TEXT NOT NULL,
    "honeypotId" TEXT NOT NULL,
    "apiProjectId" TEXT,
    "sourceIp" TEXT NOT NULL,
    "userAgent" TEXT,
    "payload" JSONB,
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "severity" "ThreatSeverity" NOT NULL DEFAULT 'MEDIUM',
    "tags" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "isFalsePositive" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "ThreatEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "LiveThreatEvent" (
    "id" TEXT NOT NULL,
    "eventType" TEXT NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "ip" TEXT NOT NULL,
    "userAgent" TEXT,
    "requestPath" TEXT,
    "statusCode" INTEGER,
    "method" TEXT,
    "headers" JSONB,
    "body" JSONB,
    "severity" "ThreatSeverity" NOT NULL DEFAULT 'MEDIUM',
    "metadata" JSONB,
    "projectId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "actionTaken" TEXT,
    "appId" TEXT,
    "authPhase" TEXT,
    "clMode" TEXT,
    "environment" TEXT,
    "responseLatencyMs" INTEGER,
    "sessionActiveAfterAction" BOOLEAN,
    "sessionId" TEXT,
    "userId" TEXT,
    "signature" TEXT,
    "previousSignature" TEXT,

    CONSTRAINT "LiveThreatEvent_pkey" PRIMARY KEY ("id")
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
CREATE TABLE "FlywheelInsight" (
    "id" TEXT NOT NULL,
    "apiProjectId" TEXT,
    "type" "InsightType" NOT NULL DEFAULT 'VULNERABILITY_TREND',
    "summary" TEXT NOT NULL,
    "details" JSONB,
    "generatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "modelVersion" TEXT,
    "confidence" DOUBLE PRECISION,
    "ownerId" TEXT,

    CONSTRAINT "FlywheelInsight_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DocumentationNode" (
    "id" TEXT NOT NULL,
    "apiProjectId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "content" JSONB NOT NULL,
    "locale" TEXT NOT NULL DEFAULT 'en',
    "version" TEXT NOT NULL DEFAULT 'latest',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DocumentationNode_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CreditBalance" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "organizationId" TEXT,
    "available" INTEGER NOT NULL DEFAULT 0,
    "consumed" INTEGER NOT NULL DEFAULT 0,
    "lastNotifiedAt" TIMESTAMP(3),
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CreditBalance_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CreditTransaction" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "apiProjectId" TEXT,
    "balanceId" TEXT,
    "amount" INTEGER NOT NULL,
    "type" "CreditTransactionType" NOT NULL,
    "description" TEXT,
    "referenceId" TEXT,
    "referenceType" TEXT,
    "reason" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "organizationId" TEXT,

    CONSTRAINT "CreditTransaction_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Subscription" (
    "id" TEXT NOT NULL,
    "plan" "SubscriptionPlan" NOT NULL,
    "status" "SubscriptionStatus" NOT NULL DEFAULT 'TRIALING',
    "provider" TEXT NOT NULL,
    "providerReference" TEXT NOT NULL,
    "seats" INTEGER NOT NULL DEFAULT 1,
    "renewsAt" TIMESTAMP(3),
    "canceledAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "userId" TEXT,
    "organizationId" TEXT,

    CONSTRAINT "Subscription_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RefundRequest" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "organizationId" TEXT,
    "subscriptionId" TEXT NOT NULL,
    "transactionId" TEXT NOT NULL,
    "paddleAdjustmentId" TEXT,
    "type" "RefundRequestType" NOT NULL,
    "status" "RefundRequestStatus" NOT NULL DEFAULT 'PENDING_APPROVAL',
    "amountPaidUsd" DOUBLE PRECISION NOT NULL,
    "usageDeductionUsd" DOUBLE PRECISION NOT NULL,
    "refundableUsd" DOUBLE PRECISION NOT NULL,
    "usageBreakdown" JSONB NOT NULL,
    "estimatedPaddleFeeUsd" DOUBLE PRECISION,
    "retainedFeeUsd" DOUBLE PRECISION,
    "requestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "resolvedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RefundRequest_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SyncState" (
    "id" TEXT NOT NULL,
    "repositoryId" TEXT NOT NULL,
    "lastSyncedAt" TIMESTAMP(3),
    "lastRevision" TEXT,
    "state" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SyncState_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "apiProjectId" TEXT,
    "action" TEXT NOT NULL,
    "resource" TEXT NOT NULL,
    "resourceId" TEXT,
    "level" "LogLevel" NOT NULL DEFAULT 'INFO',
    "message" TEXT NOT NULL,
    "details" JSONB,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "NotificationPreference" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "creditAlertsEnabled" BOOLEAN NOT NULL DEFAULT true,
    "securityAlertsEnabled" BOOLEAN NOT NULL DEFAULT true,
    "marketingOptIn" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "NotificationPreference_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Notification" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "type" "NotificationType" NOT NULL,
    "title" TEXT NOT NULL,
    "message" TEXT NOT NULL,
    "metadata" JSONB,
    "status" "NotificationStatus" NOT NULL DEFAULT 'UNREAD',
    "readAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Notification_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Account" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "providerAccountId" TEXT NOT NULL,
    "refresh_token" TEXT,
    "access_token" TEXT,
    "expires_at" INTEGER,
    "token_type" TEXT,
    "scope" TEXT,
    "id_token" TEXT,
    "session_state" TEXT,
    "oauth_token_secret" TEXT,
    "oauth_token" TEXT,
    "refresh_token_expires_in" INTEGER,

    CONSTRAINT "Account_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Session" (
    "id" TEXT NOT NULL,
    "sessionToken" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "expires" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VerificationToken" (
    "identifier" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "expires" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "VerificationToken_pkey" PRIMARY KEY ("token")
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

-- CreateTable
CREATE TABLE "AppSettings" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "description" TEXT,
    "updatedBy" TEXT,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AppSettings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AIPerformanceLog" (
    "id" TEXT NOT NULL,
    "taskType" "AITaskType" NOT NULL,
    "provider" "AIProvider" NOT NULL,
    "inputHash" TEXT NOT NULL,
    "outputSample" TEXT,
    "accuracy" DOUBLE PRECISION,
    "costUsd" DOUBLE PRECISION NOT NULL,
    "latencyMs" INTEGER NOT NULL,
    "errorOccurred" BOOLEAN NOT NULL DEFAULT false,
    "errorType" TEXT,
    "mlConfidence" DOUBLE PRECISION,
    "nlUsedAsFallback" BOOLEAN NOT NULL DEFAULT false,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AIPerformanceLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DeploymentApproval" (
    "id" TEXT NOT NULL,
    "requesterId" TEXT NOT NULL,
    "environment" "DeploymentEnvironment" NOT NULL,
    "status" "DeploymentApprovalStatus" NOT NULL DEFAULT 'PENDING',
    "branch" TEXT NOT NULL,
    "commit" TEXT NOT NULL,
    "changes" JSONB,
    "deploymentDetails" JSONB,
    "requestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "approvedById" TEXT,
    "approvedAt" TIMESTAMP(3),
    "rejectedReason" TEXT,
    "deploymentUrl" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DeploymentApproval_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserFeedback" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "type" "UserFeedbackType" NOT NULL,
    "sentiment" INTEGER,
    "category" TEXT,
    "page" TEXT,
    "title" TEXT,
    "description" TEXT,
    "metadata" JSONB,
    "votes" INTEGER NOT NULL DEFAULT 1,
    "status" "UserFeedbackStatus" NOT NULL DEFAULT 'NEW',
    "adminNotes" TEXT,
    "resolvedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "UserFeedback_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DataExport" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "status" "ExportStatus" NOT NULL DEFAULT 'PENDING',
    "downloadUrl" TEXT,
    "format" TEXT NOT NULL DEFAULT 'json',
    "includeThreats" BOOLEAN NOT NULL DEFAULT true,
    "includeAlerts" BOOLEAN NOT NULL DEFAULT true,
    "includeLogs" BOOLEAN NOT NULL DEFAULT true,
    "includeProjects" BOOLEAN NOT NULL DEFAULT true,
    "startDate" TIMESTAMP(3),
    "endDate" TIMESTAMP(3),
    "fileSize" INTEGER,
    "requestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3),
    "errorMessage" TEXT,

    CONSTRAINT "DataExport_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ConsultingJob" (
    "id" TEXT NOT NULL,
    "type" "ConsultingJobType" NOT NULL,
    "status" "ConsultingJobStatus" NOT NULL DEFAULT 'PENDING',
    "input" JSONB NOT NULL,
    "output" JSONB,
    "progress" INTEGER NOT NULL DEFAULT 0,
    "userId" TEXT NOT NULL,
    "clientId" TEXT,
    "error" TEXT,
    "priority" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ConsultingJob_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ConsultingClient" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "email" TEXT,
    "company" TEXT,
    "websiteUrl" TEXT,
    "notes" TEXT,
    "branding" JSONB,
    "shareToken" TEXT,
    "createdById" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ConsultingClient_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditReport" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "clientId" TEXT,
    "jobId" TEXT,
    "targetUrl" TEXT,
    "status" "AuditReportStatus" NOT NULL DEFAULT 'GENERATING',
    "reportJson" JSONB,
    "executiveSummary" TEXT,
    "overallScore" INTEGER,
    "criticalCount" INTEGER NOT NULL DEFAULT 0,
    "highCount" INTEGER NOT NULL DEFAULT 0,
    "mediumCount" INTEGER NOT NULL DEFAULT 0,
    "lowCount" INTEGER NOT NULL DEFAULT 0,
    "pdfUrl" TEXT,
    "shareToken" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AuditReport_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScanSchedule" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "clientId" TEXT,
    "targetUrl" TEXT NOT NULL,
    "frequency" "ScanFrequency" NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "lastRunAt" TIMESTAMP(3),
    "nextRunAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ScanSchedule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ClAuditTrail" (
    "id" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "detectEventId" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "clMode" TEXT NOT NULL,
    "authPhase" TEXT,
    "ip" TEXT,
    "userId" TEXT,
    "confirmed" BOOLEAN NOT NULL DEFAULT false,
    "confirmedAt" TIMESTAMP(3),
    "latencyMs" INTEGER,
    "success" BOOLEAN,
    "failureReason" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ClAuditTrail_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BlockedIp" (
    "id" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "ip" TEXT NOT NULL,
    "compositeScore" DOUBLE PRECISION,
    "abuseIpDbScore" DOUBLE PRECISION,
    "dfSignalScore" DOUBLE PRECISION,
    "source" TEXT NOT NULL DEFAULT 'auto',
    "reason" TEXT,
    "blockedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3),
    "unblockedAt" TIMESTAMP(3),
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "BlockedIp_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WebhookDelivery" (
    "id" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "eventType" TEXT NOT NULL,
    "targetUrl" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "hmacSignature" TEXT,
    "httpStatus" INTEGER,
    "responseBody" TEXT,
    "success" BOOLEAN NOT NULL DEFAULT false,
    "attempt" INTEGER NOT NULL DEFAULT 1,
    "maxAttempts" INTEGER NOT NULL DEFAULT 3,
    "nextRetryAt" TIMESTAMP(3),
    "error" TEXT,
    "deliveredAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "WebhookDelivery_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EnterpriseSSOConfig" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "provider" "EnterpriseSSOProvider" NOT NULL,
    "status" "EnterpriseSSOStatus" NOT NULL DEFAULT 'PENDING_SETUP',
    "displayName" TEXT NOT NULL,
    "metadataUrl" TEXT,
    "entityId" TEXT,
    "ssoUrl" TEXT,
    "sloUrl" TEXT,
    "certificate" TEXT,
    "attributeMapping" JSONB NOT NULL,
    "enforceSSO" BOOLEAN NOT NULL DEFAULT false,
    "jitProvisioning" BOOLEAN NOT NULL DEFAULT false,
    "defaultRole" TEXT NOT NULL DEFAULT 'VIEWER',
    "allowedDomains" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EnterpriseSSOConfig_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EnterpriseSSOSession" (
    "id" TEXT NOT NULL,
    "configId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "provider" "EnterpriseSSOProvider" NOT NULL,
    "idpSessionId" TEXT NOT NULL,
    "nameId" TEXT NOT NULL,
    "attributes" JSONB NOT NULL,
    "authenticatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EnterpriseSSOSession_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EnterpriseMTLSConfig" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "enforceForAllEndpoints" BOOLEAN NOT NULL DEFAULT false,
    "requiredEndpoints" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "autoRotationEnabled" BOOLEAN NOT NULL DEFAULT true,
    "autoRotationDaysBefore" INTEGER NOT NULL DEFAULT 30,
    "autoRotationNotifyDays" INTEGER[] DEFAULT ARRAY[90, 60, 30, 14, 7, 1]::INTEGER[],
    "maxValidityDays" INTEGER NOT NULL DEFAULT 365,
    "allowedKeyAlgorithms" TEXT[] DEFAULT ARRAY['RSA-2048', 'RSA-4096', 'ECDSA-P256', 'ECDSA-P384']::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EnterpriseMTLSConfig_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EnterpriseCertificate" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "configId" TEXT,
    "type" "EnterpriseCertType" NOT NULL,
    "status" "EnterpriseCertStatus" NOT NULL DEFAULT 'PENDING',
    "commonName" TEXT NOT NULL,
    "serialNumber" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "issuer" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "validFrom" TIMESTAMP(3) NOT NULL,
    "validUntil" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "revocationReason" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EnterpriseCertificate_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EnterpriseSIEMConfig" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "provider" "EnterpriseSIEMProvider" NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "endpoint" TEXT NOT NULL,
    "authToken" TEXT,
    "apiKey" TEXT,
    "hecToken" TEXT,
    "ddApiKey" TEXT,
    "ddSite" TEXT,
    "sentinelWorkspaceId" TEXT,
    "sentinelSharedKey" TEXT,
    "customHeaders" JSONB,
    "minSeverity" INTEGER NOT NULL DEFAULT 1,
    "threatTypeFilter" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EnterpriseSIEMConfig_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EnterprisePlaybook" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "priority" INTEGER NOT NULL DEFAULT 50,
    "rules" JSONB NOT NULL,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EnterprisePlaybook_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EnterpriseAccountLock" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "status" "EnterpriseAccountLockStatus" NOT NULL DEFAULT 'ACTIVE',
    "reason" TEXT NOT NULL,
    "lockedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3),
    "lockedBy" TEXT NOT NULL,
    "unlockToken" TEXT,
    "metadata" JSONB,
    "unlockedAt" TIMESTAMP(3),
    "unlockedBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EnterpriseAccountLock_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EnterpriseAccountLockHistory" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "reason" TEXT,
    "details" JSONB,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EnterpriseAccountLockHistory_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AliasTelemetryRollup" (
    "id" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "aliasOrIpKey" TEXT NOT NULL,
    "periodKey" TEXT NOT NULL,
    "requestCount" INTEGER NOT NULL DEFAULT 0,
    "uniqueEndpoints" INTEGER NOT NULL DEFAULT 0,
    "errorRate" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "avgLatencyMs" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "windowStart" TIMESTAMP(3) NOT NULL,
    "windowEnd" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AliasTelemetryRollup_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EnterpriseUsagePeriod" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "periodKey" TEXT NOT NULL,
    "periodStart" TIMESTAMP(3) NOT NULL,
    "periodEnd" TIMESTAMP(3) NOT NULL,
    "events" INTEGER NOT NULL DEFAULT 0,
    "automatedActions" INTEGER NOT NULL DEFAULT 0,
    "abuseipdbChecks" INTEGER NOT NULL DEFAULT 0,
    "apiGenerations" INTEGER NOT NULL DEFAULT 0,
    "lastUpdated" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EnterpriseUsagePeriod_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EnterpriseContract" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "orgName" TEXT NOT NULL,
    "status" "EnterpriseContractStatus" NOT NULL DEFAULT 'PENDING',
    "tier" TEXT NOT NULL,
    "annualValue" INTEGER NOT NULL,
    "monthlyEquivalent" INTEGER NOT NULL,
    "includedEndpoints" INTEGER NOT NULL,
    "startDate" TIMESTAMP(3) NOT NULL,
    "endDate" TIMESTAMP(3) NOT NULL,
    "autoRenew" BOOLEAN NOT NULL DEFAULT true,
    "poNumber" TEXT,
    "compliance" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "securityTier" TEXT NOT NULL,
    "deploymentModel" TEXT NOT NULL,
    "slaTier" TEXT NOT NULL,
    "implementationFee" INTEGER NOT NULL DEFAULT 0,
    "implementationPaid" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EnterpriseContract_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EnterpriseInvoice" (
    "id" TEXT NOT NULL,
    "contractId" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "orgName" TEXT NOT NULL,
    "invoiceNumber" TEXT NOT NULL,
    "status" "EnterpriseInvoiceStatus" NOT NULL DEFAULT 'DRAFT',
    "currency" TEXT NOT NULL DEFAULT 'USD',
    "lineItems" JSONB NOT NULL,
    "subtotal" INTEGER NOT NULL,
    "tax" INTEGER NOT NULL DEFAULT 0,
    "taxRate" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "total" INTEGER NOT NULL,
    "dueDate" TIMESTAMP(3) NOT NULL,
    "issuedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "paidAt" TIMESTAMP(3),
    "poNumber" TEXT,
    "notes" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EnterpriseInvoice_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CredentialAlias" (
    "id" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "workload" TEXT NOT NULL DEFAULT 'custom',
    "label" TEXT NOT NULL,
    "aliasKeyHash" TEXT NOT NULL,
    "state" TEXT NOT NULL DEFAULT 'active',
    "familyId" TEXT,
    "scope" TEXT,
    "tags" TEXT,
    "maxUses" INTEGER,
    "expiresAt" TIMESTAMP(3),
    "usageCount" INTEGER NOT NULL DEFAULT 0,
    "lastUsedAt" TIMESTAMP(3),
    "rotatedFromId" TEXT,
    "rotatedToId" TEXT,
    "revokedAt" TIMESTAMP(3),
    "revocationReason" TEXT,
    "bindingIpCidr" TEXT,
    "bindingRegions" TEXT[],
    "bindingTimeZone" TEXT,
    "bindingTimeStart" TEXT,
    "bindingTimeEnd" TEXT,
    "bindingWorkloadId" TEXT,
    "bindingDeviceId" TEXT,
    "bindingAppBundle" TEXT,
    "bindingAgentTools" TEXT[],
    "bindingContainerId" TEXT,
    "bindingExpectedEgressPath" TEXT,
    "bindingExpectedProcessSignature" TEXT,
    "declaredTask" TEXT,
    "declaredTaskAllowedTools" TEXT[],
    "permittedOperationClasses" TEXT[],
    "bindingExpectedModelIdentifier" TEXT,
    "ownerIdentifier" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CredentialAlias_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TrustChainRecord" (
    "chainId" TEXT NOT NULL,
    "originServiceId" TEXT NOT NULL,
    "valid" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "TrustChainRecord_pkey" PRIMARY KEY ("chainId")
);

-- CreateTable
CREATE TABLE "TrustChainHop" (
    "id" TEXT NOT NULL,
    "chainId" TEXT NOT NULL,
    "hopIndex" INTEGER NOT NULL,
    "serviceId" TEXT NOT NULL,
    "aliasId" TEXT NOT NULL,
    "hopTimestamp" BIGINT NOT NULL,
    "signature" TEXT NOT NULL,
    "parentAliasId" TEXT,
    "trust" DOUBLE PRECISION NOT NULL,
    "scope" TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "fingerprintRequestIp" TEXT,
    "fingerprintGeoCountry" TEXT,
    "fingerprintWorkloadId" TEXT,
    "fingerprintDeviceFingerprint" TEXT,
    "fingerprintContainerId" TEXT,

    CONSTRAINT "TrustChainHop_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "NewsletterSubscriber" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'active',
    "segment" TEXT NOT NULL DEFAULT 'general',
    "source" TEXT NOT NULL DEFAULT 'api',
    "consentGiven" BOOLEAN NOT NULL DEFAULT false,
    "consentAt" TIMESTAMP(3),
    "unsubscribedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "NewsletterSubscriber_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EnterpriseOnboardingRecord" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "orgName" TEXT NOT NULL,
    "contractSignedAt" TIMESTAMP(3) NOT NULL,
    "kickoffDate" TIMESTAMP(3) NOT NULL,
    "targetGoLiveDate" TIMESTAMP(3) NOT NULL,
    "csmAssignment" JSONB NOT NULL,
    "steps" JSONB NOT NULL,
    "currentPhase" TEXT NOT NULL,
    "overallProgress" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EnterpriseOnboardingRecord_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "licenses" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "email" TEXT NOT NULL,
    "product_id" TEXT NOT NULL,
    "purchase_id" TEXT NOT NULL,
    "license_key" TEXT,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "licenses_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TeamProjectAccess" (
    "id" TEXT NOT NULL,
    "teamId" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "grantedById" TEXT NOT NULL,
    "grantedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "TeamProjectAccess_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "InvoiceCounter" (
    "id" TEXT NOT NULL DEFAULT 'global',
    "seq" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "InvoiceCounter_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EnterpriseIntake" (
    "id" TEXT NOT NULL,
    "companyName" TEXT NOT NULL,
    "legalEntityName" TEXT NOT NULL,
    "contactName" TEXT NOT NULL,
    "contactEmail" TEXT NOT NULL,
    "jobTitle" TEXT NOT NULL,
    "vatNumber" TEXT,
    "estimatedEndpoints" INTEGER,
    "deploymentType" TEXT,
    "complianceFrameworks" TEXT[],
    "aiAgentCount" INTEGER,
    "billingCycle" TEXT NOT NULL,
    "preferredPayment" TEXT NOT NULL,
    "estimatedAnnualUsd" DOUBLE PRECISION NOT NULL,
    "invoiceType" TEXT NOT NULL,
    "agreementAcceptedAt" TIMESTAMP(3) NOT NULL,
    "acceptanceIp" TEXT,
    "message" TEXT,
    "status" TEXT NOT NULL DEFAULT 'pending_contract',
    "invoiceRef" TEXT,
    "invoiceSentAt" TIMESTAMP(3),
    "paymentConfirmedAt" TIMESTAMP(3),
    "paymentReceiptRef" TEXT,
    "provisionedUserId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EnterpriseIntake_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RateLimitBucket" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "windowStart" TIMESTAMP(3) NOT NULL,
    "count" INTEGER NOT NULL DEFAULT 1,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RateLimitBucket_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RedisFallback" (
    "key" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RedisFallback_pkey" PRIMARY KEY ("key")
);

-- CreateTable
CREATE TABLE "CustomRule" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "priority" INTEGER NOT NULL DEFAULT 500,
    "conditions" JSONB NOT NULL,
    "conditionLogic" TEXT NOT NULL DEFAULT 'AND',
    "action" JSONB NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CustomRule_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE INDEX "UserApiKey_userId_idx" ON "UserApiKey"("userId");

-- CreateIndex
CREATE INDEX "UserApiKey_type_idx" ON "UserApiKey"("type");

-- CreateIndex
CREATE UNIQUE INDEX "UserApiKey_userId_type_key" ON "UserApiKey"("userId", "type");

-- CreateIndex
CREATE UNIQUE INDEX "Team_slug_key" ON "Team"("slug");

-- CreateIndex
CREATE UNIQUE INDEX "TeamMember_teamId_userId_key" ON "TeamMember"("teamId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "TeamInvitation_token_key" ON "TeamInvitation"("token");

-- CreateIndex
CREATE UNIQUE INDEX "TeamInvitation_teamId_email_key" ON "TeamInvitation"("teamId", "email");

-- CreateIndex
CREATE UNIQUE INDEX "Organization_slug_key" ON "Organization"("slug");

-- CreateIndex
CREATE UNIQUE INDEX "OrganizationMember_organizationId_userId_key" ON "OrganizationMember"("organizationId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "ApiProject_slug_key" ON "ApiProject"("slug");

-- CreateIndex
CREATE UNIQUE INDEX "ApiProject_repositoryId_key" ON "ApiProject"("repositoryId");

-- CreateIndex
CREATE UNIQUE INDEX "ApiProject_surveillanceApiKey_key" ON "ApiProject"("surveillanceApiKey");

-- CreateIndex
CREATE UNIQUE INDEX "ApiProject_surveillanceKeyId_key" ON "ApiProject"("surveillanceKeyId");

-- CreateIndex
CREATE UNIQUE INDEX "OperatorKey_operatorId_key" ON "OperatorKey"("operatorId");

-- CreateIndex
CREATE UNIQUE INDEX "Repository_externalId_key" ON "Repository"("externalId");

-- CreateIndex
CREATE UNIQUE INDEX "Honeypot_slug_key" ON "Honeypot"("slug");

-- CreateIndex
CREATE INDEX "Honeypot_consultingClientId_idx" ON "Honeypot"("consultingClientId");

-- CreateIndex
CREATE INDEX "HoneypotTestResult_honeypotId_idx" ON "HoneypotTestResult"("honeypotId");

-- CreateIndex
CREATE INDEX "HoneypotTestResult_userId_idx" ON "HoneypotTestResult"("userId");

-- CreateIndex
CREATE INDEX "HoneypotTestResult_createdAt_idx" ON "HoneypotTestResult"("createdAt");

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
CREATE INDEX "LiveThreatEvent_projectId_idx" ON "LiveThreatEvent"("projectId");

-- CreateIndex
CREATE INDEX "LiveThreatEvent_timestamp_idx" ON "LiveThreatEvent"("timestamp");

-- CreateIndex
CREATE INDEX "LiveThreatEvent_eventType_idx" ON "LiveThreatEvent"("eventType");

-- CreateIndex
CREATE INDEX "LiveThreatEvent_severity_idx" ON "LiveThreatEvent"("severity");

-- CreateIndex
CREATE INDEX "LiveThreatEvent_ip_idx" ON "LiveThreatEvent"("ip");

-- CreateIndex
CREATE INDEX "LiveThreatEvent_authPhase_idx" ON "LiveThreatEvent"("authPhase");

-- CreateIndex
CREATE INDEX "LiveThreatEvent_actionTaken_idx" ON "LiveThreatEvent"("actionTaken");

-- CreateIndex
CREATE INDEX "LiveThreatEvent_projectId_ip_severity_timestamp_idx" ON "LiveThreatEvent"("projectId", "ip", "severity", "timestamp");

-- CreateIndex
CREATE INDEX "LiveThreatEvent_projectId_ip_eventType_timestamp_idx" ON "LiveThreatEvent"("projectId", "ip", "eventType", "timestamp");

-- CreateIndex
CREATE INDEX "FlywheelInsight_ownerId_idx" ON "FlywheelInsight"("ownerId");

-- CreateIndex
CREATE INDEX "FlywheelInsight_apiProjectId_idx" ON "FlywheelInsight"("apiProjectId");

-- CreateIndex
CREATE UNIQUE INDEX "CreditBalance_userId_key" ON "CreditBalance"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "CreditBalance_organizationId_key" ON "CreditBalance"("organizationId");

-- CreateIndex
CREATE INDEX "CreditTransaction_userId_idx" ON "CreditTransaction"("userId");

-- CreateIndex
CREATE INDEX "CreditTransaction_organizationId_idx" ON "CreditTransaction"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "Subscription_providerReference_key" ON "Subscription"("providerReference");

-- CreateIndex
CREATE UNIQUE INDEX "RefundRequest_paddleAdjustmentId_key" ON "RefundRequest"("paddleAdjustmentId");

-- CreateIndex
CREATE INDEX "RefundRequest_subscriptionId_idx" ON "RefundRequest"("subscriptionId");

-- CreateIndex
CREATE INDEX "RefundRequest_status_idx" ON "RefundRequest"("status");

-- CreateIndex
CREATE UNIQUE INDEX "NotificationPreference_userId_key" ON "NotificationPreference"("userId");

-- CreateIndex
CREATE INDEX "Notification_userId_idx" ON "Notification"("userId");

-- CreateIndex
CREATE INDEX "Notification_type_idx" ON "Notification"("type");

-- CreateIndex
CREATE INDEX "Notification_status_idx" ON "Notification"("status");

-- CreateIndex
CREATE INDEX "Notification_createdAt_idx" ON "Notification"("createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "Account_provider_providerAccountId_key" ON "Account"("provider", "providerAccountId");

-- CreateIndex
CREATE UNIQUE INDEX "Session_sessionToken_key" ON "Session"("sessionToken");

-- CreateIndex
CREATE UNIQUE INDEX "VerificationToken_identifier_token_key" ON "VerificationToken"("identifier", "token");

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

-- CreateIndex
CREATE UNIQUE INDEX "AppSettings_key_key" ON "AppSettings"("key");

-- CreateIndex
CREATE INDEX "AppSettings_key_idx" ON "AppSettings"("key");

-- CreateIndex
CREATE INDEX "AIPerformanceLog_taskType_idx" ON "AIPerformanceLog"("taskType");

-- CreateIndex
CREATE INDEX "AIPerformanceLog_provider_idx" ON "AIPerformanceLog"("provider");

-- CreateIndex
CREATE INDEX "AIPerformanceLog_createdAt_idx" ON "AIPerformanceLog"("createdAt");

-- CreateIndex
CREATE INDEX "AIPerformanceLog_errorOccurred_idx" ON "AIPerformanceLog"("errorOccurred");

-- CreateIndex
CREATE INDEX "DeploymentApproval_requesterId_idx" ON "DeploymentApproval"("requesterId");

-- CreateIndex
CREATE INDEX "DeploymentApproval_status_idx" ON "DeploymentApproval"("status");

-- CreateIndex
CREATE INDEX "DeploymentApproval_environment_idx" ON "DeploymentApproval"("environment");

-- CreateIndex
CREATE INDEX "DeploymentApproval_requestedAt_idx" ON "DeploymentApproval"("requestedAt");

-- CreateIndex
CREATE INDEX "DeploymentApproval_expiresAt_idx" ON "DeploymentApproval"("expiresAt");

-- CreateIndex
CREATE INDEX "UserFeedback_userId_idx" ON "UserFeedback"("userId");

-- CreateIndex
CREATE INDEX "UserFeedback_type_idx" ON "UserFeedback"("type");

-- CreateIndex
CREATE INDEX "UserFeedback_status_idx" ON "UserFeedback"("status");

-- CreateIndex
CREATE INDEX "UserFeedback_category_idx" ON "UserFeedback"("category");

-- CreateIndex
CREATE INDEX "UserFeedback_sentiment_idx" ON "UserFeedback"("sentiment");

-- CreateIndex
CREATE INDEX "UserFeedback_createdAt_idx" ON "UserFeedback"("createdAt");

-- CreateIndex
CREATE INDEX "DataExport_userId_idx" ON "DataExport"("userId");

-- CreateIndex
CREATE INDEX "DataExport_status_idx" ON "DataExport"("status");

-- CreateIndex
CREATE INDEX "DataExport_requestedAt_idx" ON "DataExport"("requestedAt");

-- CreateIndex
CREATE INDEX "DataExport_expiresAt_idx" ON "DataExport"("expiresAt");

-- CreateIndex
CREATE INDEX "ConsultingJob_status_priority_idx" ON "ConsultingJob"("status", "priority");

-- CreateIndex
CREATE INDEX "ConsultingJob_userId_idx" ON "ConsultingJob"("userId");

-- CreateIndex
CREATE INDEX "ConsultingJob_clientId_idx" ON "ConsultingJob"("clientId");

-- CreateIndex
CREATE INDEX "ConsultingJob_type_idx" ON "ConsultingJob"("type");

-- CreateIndex
CREATE INDEX "ConsultingJob_createdAt_idx" ON "ConsultingJob"("createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "ConsultingClient_shareToken_key" ON "ConsultingClient"("shareToken");

-- CreateIndex
CREATE INDEX "ConsultingClient_createdById_idx" ON "ConsultingClient"("createdById");

-- CreateIndex
CREATE INDEX "ConsultingClient_email_idx" ON "ConsultingClient"("email");

-- CreateIndex
CREATE INDEX "ConsultingClient_shareToken_idx" ON "ConsultingClient"("shareToken");

-- CreateIndex
CREATE UNIQUE INDEX "AuditReport_jobId_key" ON "AuditReport"("jobId");

-- CreateIndex
CREATE UNIQUE INDEX "AuditReport_shareToken_key" ON "AuditReport"("shareToken");

-- CreateIndex
CREATE INDEX "AuditReport_userId_idx" ON "AuditReport"("userId");

-- CreateIndex
CREATE INDEX "AuditReport_clientId_idx" ON "AuditReport"("clientId");

-- CreateIndex
CREATE INDEX "AuditReport_status_idx" ON "AuditReport"("status");

-- CreateIndex
CREATE INDEX "AuditReport_createdAt_idx" ON "AuditReport"("createdAt");

-- CreateIndex
CREATE INDEX "AuditReport_shareToken_idx" ON "AuditReport"("shareToken");

-- CreateIndex
CREATE INDEX "ScanSchedule_userId_idx" ON "ScanSchedule"("userId");

-- CreateIndex
CREATE INDEX "ScanSchedule_isActive_nextRunAt_idx" ON "ScanSchedule"("isActive", "nextRunAt");

-- CreateIndex
CREATE INDEX "ClAuditTrail_projectId_idx" ON "ClAuditTrail"("projectId");

-- CreateIndex
CREATE INDEX "ClAuditTrail_detectEventId_idx" ON "ClAuditTrail"("detectEventId");

-- CreateIndex
CREATE INDEX "ClAuditTrail_createdAt_idx" ON "ClAuditTrail"("createdAt");

-- CreateIndex
CREATE INDEX "ClAuditTrail_confirmed_idx" ON "ClAuditTrail"("confirmed");

-- CreateIndex
CREATE INDEX "ClAuditTrail_action_idx" ON "ClAuditTrail"("action");

-- CreateIndex
CREATE INDEX "BlockedIp_projectId_idx" ON "BlockedIp"("projectId");

-- CreateIndex
CREATE INDEX "BlockedIp_ip_idx" ON "BlockedIp"("ip");

-- CreateIndex
CREATE INDEX "BlockedIp_blockedAt_idx" ON "BlockedIp"("blockedAt");

-- CreateIndex
CREATE INDEX "BlockedIp_expiresAt_idx" ON "BlockedIp"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "BlockedIp_projectId_ip_key" ON "BlockedIp"("projectId", "ip");

-- CreateIndex
CREATE INDEX "WebhookDelivery_projectId_idx" ON "WebhookDelivery"("projectId");

-- CreateIndex
CREATE INDEX "WebhookDelivery_success_idx" ON "WebhookDelivery"("success");

-- CreateIndex
CREATE INDEX "WebhookDelivery_createdAt_idx" ON "WebhookDelivery"("createdAt");

-- CreateIndex
CREATE INDEX "WebhookDelivery_nextRetryAt_idx" ON "WebhookDelivery"("nextRetryAt");

-- CreateIndex
CREATE INDEX "EnterpriseSSOConfig_orgId_idx" ON "EnterpriseSSOConfig"("orgId");

-- CreateIndex
CREATE INDEX "EnterpriseSSOConfig_provider_idx" ON "EnterpriseSSOConfig"("provider");

-- CreateIndex
CREATE INDEX "EnterpriseSSOConfig_status_idx" ON "EnterpriseSSOConfig"("status");

-- CreateIndex
CREATE INDEX "EnterpriseSSOSession_configId_idx" ON "EnterpriseSSOSession"("configId");

-- CreateIndex
CREATE INDEX "EnterpriseSSOSession_userId_idx" ON "EnterpriseSSOSession"("userId");

-- CreateIndex
CREATE INDEX "EnterpriseSSOSession_expiresAt_idx" ON "EnterpriseSSOSession"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "EnterpriseMTLSConfig_orgId_key" ON "EnterpriseMTLSConfig"("orgId");

-- CreateIndex
CREATE INDEX "EnterpriseMTLSConfig_orgId_idx" ON "EnterpriseMTLSConfig"("orgId");

-- CreateIndex
CREATE UNIQUE INDEX "EnterpriseCertificate_serialNumber_key" ON "EnterpriseCertificate"("serialNumber");

-- CreateIndex
CREATE INDEX "EnterpriseCertificate_orgId_idx" ON "EnterpriseCertificate"("orgId");

-- CreateIndex
CREATE INDEX "EnterpriseCertificate_status_idx" ON "EnterpriseCertificate"("status");

-- CreateIndex
CREATE INDEX "EnterpriseCertificate_fingerprint_idx" ON "EnterpriseCertificate"("fingerprint");

-- CreateIndex
CREATE INDEX "EnterpriseCertificate_validUntil_idx" ON "EnterpriseCertificate"("validUntil");

-- CreateIndex
CREATE INDEX "EnterpriseSIEMConfig_orgId_idx" ON "EnterpriseSIEMConfig"("orgId");

-- CreateIndex
CREATE INDEX "EnterpriseSIEMConfig_provider_idx" ON "EnterpriseSIEMConfig"("provider");

-- CreateIndex
CREATE INDEX "EnterpriseSIEMConfig_enabled_idx" ON "EnterpriseSIEMConfig"("enabled");

-- CreateIndex
CREATE INDEX "EnterprisePlaybook_orgId_idx" ON "EnterprisePlaybook"("orgId");

-- CreateIndex
CREATE INDEX "EnterprisePlaybook_enabled_idx" ON "EnterprisePlaybook"("enabled");

-- CreateIndex
CREATE INDEX "EnterprisePlaybook_priority_idx" ON "EnterprisePlaybook"("priority");

-- CreateIndex
CREATE INDEX "EnterpriseAccountLock_userId_idx" ON "EnterpriseAccountLock"("userId");

-- CreateIndex
CREATE INDEX "EnterpriseAccountLock_status_idx" ON "EnterpriseAccountLock"("status");

-- CreateIndex
CREATE INDEX "EnterpriseAccountLock_expiresAt_idx" ON "EnterpriseAccountLock"("expiresAt");

-- CreateIndex
CREATE INDEX "EnterpriseAccountLockHistory_userId_idx" ON "EnterpriseAccountLockHistory"("userId");

-- CreateIndex
CREATE INDEX "EnterpriseAccountLockHistory_timestamp_idx" ON "EnterpriseAccountLockHistory"("timestamp");

-- CreateIndex
CREATE INDEX "AliasTelemetryRollup_projectId_idx" ON "AliasTelemetryRollup"("projectId");

-- CreateIndex
CREATE INDEX "AliasTelemetryRollup_periodKey_idx" ON "AliasTelemetryRollup"("periodKey");

-- CreateIndex
CREATE INDEX "AliasTelemetryRollup_windowStart_idx" ON "AliasTelemetryRollup"("windowStart");

-- CreateIndex
CREATE UNIQUE INDEX "AliasTelemetryRollup_projectId_aliasOrIpKey_periodKey_key" ON "AliasTelemetryRollup"("projectId", "aliasOrIpKey", "periodKey");

-- CreateIndex
CREATE INDEX "EnterpriseUsagePeriod_orgId_idx" ON "EnterpriseUsagePeriod"("orgId");

-- CreateIndex
CREATE INDEX "EnterpriseUsagePeriod_periodStart_idx" ON "EnterpriseUsagePeriod"("periodStart");

-- CreateIndex
CREATE UNIQUE INDEX "EnterpriseUsagePeriod_orgId_periodKey_key" ON "EnterpriseUsagePeriod"("orgId", "periodKey");

-- CreateIndex
CREATE INDEX "EnterpriseContract_orgId_idx" ON "EnterpriseContract"("orgId");

-- CreateIndex
CREATE INDEX "EnterpriseContract_status_idx" ON "EnterpriseContract"("status");

-- CreateIndex
CREATE UNIQUE INDEX "EnterpriseInvoice_invoiceNumber_key" ON "EnterpriseInvoice"("invoiceNumber");

-- CreateIndex
CREATE INDEX "EnterpriseInvoice_contractId_idx" ON "EnterpriseInvoice"("contractId");

-- CreateIndex
CREATE INDEX "EnterpriseInvoice_orgId_idx" ON "EnterpriseInvoice"("orgId");

-- CreateIndex
CREATE INDEX "EnterpriseInvoice_status_idx" ON "EnterpriseInvoice"("status");

-- CreateIndex
CREATE INDEX "EnterpriseInvoice_dueDate_idx" ON "EnterpriseInvoice"("dueDate");

-- CreateIndex
CREATE INDEX "CredentialAlias_projectId_idx" ON "CredentialAlias"("projectId");

-- CreateIndex
CREATE INDEX "CredentialAlias_state_idx" ON "CredentialAlias"("state");

-- CreateIndex
CREATE INDEX "CredentialAlias_familyId_idx" ON "CredentialAlias"("familyId");

-- CreateIndex
CREATE INDEX "CredentialAlias_rotatedFromId_idx" ON "CredentialAlias"("rotatedFromId");

-- CreateIndex
CREATE INDEX "TrustChainRecord_originServiceId_idx" ON "TrustChainRecord"("originServiceId");

-- CreateIndex
CREATE INDEX "TrustChainHop_chainId_idx" ON "TrustChainHop"("chainId");

-- CreateIndex
CREATE INDEX "TrustChainHop_aliasId_idx" ON "TrustChainHop"("aliasId");

-- CreateIndex
CREATE UNIQUE INDEX "TrustChainHop_chainId_hopIndex_key" ON "TrustChainHop"("chainId", "hopIndex");

-- CreateIndex
CREATE UNIQUE INDEX "NewsletterSubscriber_email_key" ON "NewsletterSubscriber"("email");

-- CreateIndex
CREATE INDEX "NewsletterSubscriber_email_idx" ON "NewsletterSubscriber"("email");

-- CreateIndex
CREATE INDEX "NewsletterSubscriber_status_idx" ON "NewsletterSubscriber"("status");

-- CreateIndex
CREATE UNIQUE INDEX "EnterpriseOnboardingRecord_orgId_key" ON "EnterpriseOnboardingRecord"("orgId");

-- CreateIndex
CREATE INDEX "EnterpriseOnboardingRecord_orgId_idx" ON "EnterpriseOnboardingRecord"("orgId");

-- CreateIndex
CREATE INDEX "EnterpriseOnboardingRecord_currentPhase_idx" ON "EnterpriseOnboardingRecord"("currentPhase");

-- CreateIndex
CREATE UNIQUE INDEX "licenses_email_key" ON "licenses"("email");

-- CreateIndex
CREATE UNIQUE INDEX "TeamProjectAccess_teamId_projectId_key" ON "TeamProjectAccess"("teamId", "projectId");

-- CreateIndex
CREATE UNIQUE INDEX "RateLimitBucket_key_key" ON "RateLimitBucket"("key");

-- CreateIndex
CREATE INDEX "RateLimitBucket_windowStart_idx" ON "RateLimitBucket"("windowStart");

-- CreateIndex
CREATE INDEX "idx_redis_fallback_expires_at" ON "RedisFallback"("expires_at");

-- CreateIndex
CREATE INDEX "CustomRule_userId_idx" ON "CustomRule"("userId");

-- CreateIndex
CREATE INDEX "CustomRule_priority_idx" ON "CustomRule"("priority");

-- AddForeignKey
ALTER TABLE "UserApiKey" ADD CONSTRAINT "UserApiKey_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Team" ADD CONSTRAINT "Team_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Team" ADD CONSTRAINT "Team_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TeamMember" ADD CONSTRAINT "TeamMember_teamId_fkey" FOREIGN KEY ("teamId") REFERENCES "Team"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TeamMember" ADD CONSTRAINT "TeamMember_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TeamInvitation" ADD CONSTRAINT "TeamInvitation_invitedById_fkey" FOREIGN KEY ("invitedById") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TeamInvitation" ADD CONSTRAINT "TeamInvitation_teamId_fkey" FOREIGN KEY ("teamId") REFERENCES "Team"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Organization" ADD CONSTRAINT "Organization_ownerId_fkey" FOREIGN KEY ("ownerId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OrganizationMember" ADD CONSTRAINT "OrganizationMember_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OrganizationMember" ADD CONSTRAINT "OrganizationMember_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ApiProject" ADD CONSTRAINT "ApiProject_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ApiProject" ADD CONSTRAINT "ApiProject_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ApiProject" ADD CONSTRAINT "ApiProject_repositoryId_fkey" FOREIGN KEY ("repositoryId") REFERENCES "Repository"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ApiProject" ADD CONSTRAINT "ApiProject_teamId_fkey" FOREIGN KEY ("teamId") REFERENCES "Team"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Repository" ADD CONSTRAINT "Repository_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Repository" ADD CONSTRAINT "Repository_ownerId_fkey" FOREIGN KEY ("ownerId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Repository" ADD CONSTRAINT "Repository_teamId_fkey" FOREIGN KEY ("teamId") REFERENCES "Team"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Honeypot" ADD CONSTRAINT "Honeypot_apiProjectId_fkey" FOREIGN KEY ("apiProjectId") REFERENCES "ApiProject"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Honeypot" ADD CONSTRAINT "Honeypot_consultingClientId_fkey" FOREIGN KEY ("consultingClientId") REFERENCES "ConsultingClient"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Honeypot" ADD CONSTRAINT "Honeypot_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Honeypot" ADD CONSTRAINT "Honeypot_ownerId_fkey" FOREIGN KEY ("ownerId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Honeypot" ADD CONSTRAINT "Honeypot_repositoryId_fkey" FOREIGN KEY ("repositoryId") REFERENCES "Repository"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Honeypot" ADD CONSTRAINT "Honeypot_teamId_fkey" FOREIGN KEY ("teamId") REFERENCES "Team"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "HoneypotTestResult" ADD CONSTRAINT "HoneypotTestResult_honeypotId_fkey" FOREIGN KEY ("honeypotId") REFERENCES "Honeypot"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "HoneypotTestResult" ADD CONSTRAINT "HoneypotTestResult_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "HoneypotTraffic" ADD CONSTRAINT "HoneypotTraffic_honeypotId_fkey" FOREIGN KEY ("honeypotId") REFERENCES "Honeypot"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "HoneypotAlert" ADD CONSTRAINT "HoneypotAlert_honeypotId_fkey" FOREIGN KEY ("honeypotId") REFERENCES "Honeypot"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ThreatEvent" ADD CONSTRAINT "ThreatEvent_apiProjectId_fkey" FOREIGN KEY ("apiProjectId") REFERENCES "ApiProject"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ThreatEvent" ADD CONSTRAINT "ThreatEvent_honeypotId_fkey" FOREIGN KEY ("honeypotId") REFERENCES "Honeypot"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "LiveThreatEvent" ADD CONSTRAINT "LiveThreatEvent_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "ApiProject"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AnomalyTrainingData" ADD CONSTRAINT "AnomalyTrainingData_honeypotId_fkey" FOREIGN KEY ("honeypotId") REFERENCES "Honeypot"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FlywheelInsight" ADD CONSTRAINT "FlywheelInsight_apiProjectId_fkey" FOREIGN KEY ("apiProjectId") REFERENCES "ApiProject"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FlywheelInsight" ADD CONSTRAINT "FlywheelInsight_ownerId_fkey" FOREIGN KEY ("ownerId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DocumentationNode" ADD CONSTRAINT "DocumentationNode_apiProjectId_fkey" FOREIGN KEY ("apiProjectId") REFERENCES "ApiProject"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CreditBalance" ADD CONSTRAINT "CreditBalance_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CreditBalance" ADD CONSTRAINT "CreditBalance_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CreditTransaction" ADD CONSTRAINT "CreditTransaction_apiProjectId_fkey" FOREIGN KEY ("apiProjectId") REFERENCES "ApiProject"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CreditTransaction" ADD CONSTRAINT "CreditTransaction_balanceId_fkey" FOREIGN KEY ("balanceId") REFERENCES "CreditBalance"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CreditTransaction" ADD CONSTRAINT "CreditTransaction_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CreditTransaction" ADD CONSTRAINT "CreditTransaction_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Subscription" ADD CONSTRAINT "Subscription_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Subscription" ADD CONSTRAINT "Subscription_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RefundRequest" ADD CONSTRAINT "RefundRequest_subscriptionId_fkey" FOREIGN KEY ("subscriptionId") REFERENCES "Subscription"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RefundRequest" ADD CONSTRAINT "RefundRequest_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RefundRequest" ADD CONSTRAINT "RefundRequest_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SyncState" ADD CONSTRAINT "SyncState_repositoryId_fkey" FOREIGN KEY ("repositoryId") REFERENCES "Repository"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditLog" ADD CONSTRAINT "AuditLog_apiProjectId_fkey" FOREIGN KEY ("apiProjectId") REFERENCES "ApiProject"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditLog" ADD CONSTRAINT "AuditLog_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "NotificationPreference" ADD CONSTRAINT "NotificationPreference_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Notification" ADD CONSTRAINT "Notification_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Account" ADD CONSTRAINT "Account_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Session" ADD CONSTRAINT "Session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BetaUser" ADD CONSTRAINT "BetaUser_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BetaFeedback" ADD CONSTRAINT "BetaFeedback_betaUserId_fkey" FOREIGN KEY ("betaUserId") REFERENCES "BetaUser"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BetaFeedback" ADD CONSTRAINT "BetaFeedback_scenarioId_fkey" FOREIGN KEY ("scenarioId") REFERENCES "TestScenario"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "APIMonitor" ADD CONSTRAINT "APIMonitor_teamId_fkey" FOREIGN KEY ("teamId") REFERENCES "Team"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "APIMonitor" ADD CONSTRAINT "APIMonitor_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MonitorCheck" ADD CONSTRAINT "MonitorCheck_monitorId_fkey" FOREIGN KEY ("monitorId") REFERENCES "APIMonitor"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MonitorIncident" ADD CONSTRAINT "MonitorIncident_monitorId_fkey" FOREIGN KEY ("monitorId") REFERENCES "APIMonitor"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Secret" ADD CONSTRAINT "Secret_teamId_fkey" FOREIGN KEY ("teamId") REFERENCES "Team"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Secret" ADD CONSTRAINT "Secret_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

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
ALTER TABLE "SupportTicket" ADD CONSTRAINT "SupportTicket_assignedToId_fkey" FOREIGN KEY ("assignedToId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SupportTicket" ADD CONSTRAINT "SupportTicket_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TicketMessage" ADD CONSTRAINT "TicketMessage_authorId_fkey" FOREIGN KEY ("authorId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TicketMessage" ADD CONSTRAINT "TicketMessage_ticketId_fkey" FOREIGN KEY ("ticketId") REFERENCES "SupportTicket"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DeploymentApproval" ADD CONSTRAINT "DeploymentApproval_approvedById_fkey" FOREIGN KEY ("approvedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DeploymentApproval" ADD CONSTRAINT "DeploymentApproval_requesterId_fkey" FOREIGN KEY ("requesterId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserFeedback" ADD CONSTRAINT "UserFeedback_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DataExport" ADD CONSTRAINT "DataExport_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ConsultingJob" ADD CONSTRAINT "ConsultingJob_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "ConsultingClient"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ConsultingJob" ADD CONSTRAINT "ConsultingJob_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ConsultingClient" ADD CONSTRAINT "ConsultingClient_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditReport" ADD CONSTRAINT "AuditReport_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "ConsultingClient"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditReport" ADD CONSTRAINT "AuditReport_jobId_fkey" FOREIGN KEY ("jobId") REFERENCES "ConsultingJob"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditReport" ADD CONSTRAINT "AuditReport_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanSchedule" ADD CONSTRAINT "ScanSchedule_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "ConsultingClient"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanSchedule" ADD CONSTRAINT "ScanSchedule_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ClAuditTrail" ADD CONSTRAINT "ClAuditTrail_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "ApiProject"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BlockedIp" ADD CONSTRAINT "BlockedIp_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "ApiProject"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WebhookDelivery" ADD CONSTRAINT "WebhookDelivery_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "ApiProject"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EnterpriseSSOSession" ADD CONSTRAINT "EnterpriseSSOSession_configId_fkey" FOREIGN KEY ("configId") REFERENCES "EnterpriseSSOConfig"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EnterpriseCertificate" ADD CONSTRAINT "EnterpriseCertificate_configId_fkey" FOREIGN KEY ("configId") REFERENCES "EnterpriseMTLSConfig"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EnterpriseInvoice" ADD CONSTRAINT "EnterpriseInvoice_contractId_fkey" FOREIGN KEY ("contractId") REFERENCES "EnterpriseContract"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CredentialAlias" ADD CONSTRAINT "CredentialAlias_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "ApiProject"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TrustChainHop" ADD CONSTRAINT "TrustChainHop_chainId_fkey" FOREIGN KEY ("chainId") REFERENCES "TrustChainRecord"("chainId") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TeamProjectAccess" ADD CONSTRAINT "TeamProjectAccess_teamId_fkey" FOREIGN KEY ("teamId") REFERENCES "Team"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TeamProjectAccess" ADD CONSTRAINT "TeamProjectAccess_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "ApiProject"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TeamProjectAccess" ADD CONSTRAINT "TeamProjectAccess_grantedById_fkey" FOREIGN KEY ("grantedById") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

