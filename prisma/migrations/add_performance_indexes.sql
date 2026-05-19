-- Performance optimization indexes for ApiForge database
-- Run this migration to improve query performance

-- User indexes
CREATE INDEX IF NOT EXISTS idx_user_email ON "User"(email);
CREATE INDEX IF NOT EXISTS idx_user_role ON "User"(role);
CREATE INDEX IF NOT EXISTS idx_user_created_at ON "User"("createdAt" DESC);

-- Team indexes
CREATE INDEX IF NOT EXISTS idx_team_slug ON "Team"(slug);
CREATE INDEX IF NOT EXISTS idx_team_organization_id ON "Team"("organizationId");
CREATE INDEX IF NOT EXISTS idx_team_created_by ON "Team"("createdById");

-- TeamMember indexes
CREATE INDEX IF NOT EXISTS idx_team_member_user_id ON "TeamMember"("userId");
CREATE INDEX IF NOT EXISTS idx_team_member_team_id ON "TeamMember"("teamId");

-- Organization indexes
CREATE INDEX IF NOT EXISTS idx_organization_slug ON "Organization"(slug);
CREATE INDEX IF NOT EXISTS idx_organization_owner_id ON "Organization"("ownerId");

-- OrganizationMember indexes
CREATE INDEX IF NOT EXISTS idx_org_member_user_id ON "OrganizationMember"("userId");
CREATE INDEX IF NOT EXISTS idx_org_member_org_id ON "OrganizationMember"("organizationId");

-- ApiProject indexes
CREATE INDEX IF NOT EXISTS idx_api_project_slug ON "ApiProject"(slug);
CREATE INDEX IF NOT EXISTS idx_api_project_created_by ON "ApiProject"("createdById");
CREATE INDEX IF NOT EXISTS idx_api_project_team_id ON "ApiProject"("teamId");
CREATE INDEX IF NOT EXISTS idx_api_project_org_id ON "ApiProject"("organizationId");
CREATE INDEX IF NOT EXISTS idx_api_project_created_at ON "ApiProject"("createdAt" DESC);

-- Repository indexes
CREATE INDEX IF NOT EXISTS idx_repository_external_id ON "Repository"("externalId");
CREATE INDEX IF NOT EXISTS idx_repository_owner_id ON "Repository"("ownerId");
CREATE INDEX IF NOT EXISTS idx_repository_status ON "Repository"(status);
CREATE INDEX IF NOT EXISTS idx_repository_team_id ON "Repository"("teamId");
CREATE INDEX IF NOT EXISTS idx_repository_org_id ON "Repository"("organizationId");

-- Honeypot indexes
CREATE INDEX IF NOT EXISTS idx_honeypot_slug ON "Honeypot"(slug);
CREATE INDEX IF NOT EXISTS idx_honeypot_status ON "Honeypot"(status);
CREATE INDEX IF NOT EXISTS idx_honeypot_owner_id ON "Honeypot"("ownerId");
CREATE INDEX IF NOT EXISTS idx_honeypot_team_id ON "Honeypot"("teamId");
CREATE INDEX IF NOT EXISTS idx_honeypot_org_id ON "Honeypot"("organizationId");
CREATE INDEX IF NOT EXISTS idx_honeypot_api_project_id ON "Honeypot"("apiProjectId");
CREATE INDEX IF NOT EXISTS idx_honeypot_created_at ON "Honeypot"("createdAt" DESC);

-- ThreatEvent indexes (critical for performance)
CREATE INDEX IF NOT EXISTS idx_threat_event_honeypot_id ON "ThreatEvent"("honeypotId");
CREATE INDEX IF NOT EXISTS idx_threat_event_api_project_id ON "ThreatEvent"("apiProjectId");
CREATE INDEX IF NOT EXISTS idx_threat_event_detected_at ON "ThreatEvent"("detectedAt" DESC);
CREATE INDEX IF NOT EXISTS idx_threat_event_severity ON "ThreatEvent"(severity);
CREATE INDEX IF NOT EXISTS idx_threat_event_source_ip ON "ThreatEvent"("sourceIp");
CREATE INDEX IF NOT EXISTS idx_threat_event_false_positive ON "ThreatEvent"("isFalsePositive");

-- Composite index for threat queries
CREATE INDEX IF NOT EXISTS idx_threat_event_honeypot_detected ON "ThreatEvent"("honeypotId", "detectedAt" DESC);
CREATE INDEX IF NOT EXISTS idx_threat_event_severity_detected ON "ThreatEvent"(severity, "detectedAt" DESC);

-- FlywheelInsight indexes
CREATE INDEX IF NOT EXISTS idx_flywheel_insight_api_project_id ON "FlywheelInsight"("apiProjectId");
CREATE INDEX IF NOT EXISTS idx_flywheel_insight_generated_at ON "FlywheelInsight"("generatedAt" DESC);
CREATE INDEX IF NOT EXISTS idx_flywheel_insight_type ON "FlywheelInsight"(type);

-- DocumentationNode indexes
CREATE INDEX IF NOT EXISTS idx_doc_node_api_project_id ON "DocumentationNode"("apiProjectId");
CREATE INDEX IF NOT EXISTS idx_doc_node_locale ON "DocumentationNode"(locale);
CREATE INDEX IF NOT EXISTS idx_doc_node_version ON "DocumentationNode"(version);

-- CreditBalance indexes
CREATE INDEX IF NOT EXISTS idx_credit_balance_user_id ON "CreditBalance"("userId");
CREATE INDEX IF NOT EXISTS idx_credit_balance_org_id ON "CreditBalance"("organizationId");

-- CreditTransaction indexes
CREATE INDEX IF NOT EXISTS idx_credit_transaction_balance_id ON "CreditTransaction"("balanceId");
CREATE INDEX IF NOT EXISTS idx_credit_transaction_api_project_id ON "CreditTransaction"("apiProjectId");
CREATE INDEX IF NOT EXISTS idx_credit_transaction_created_at ON "CreditTransaction"("createdAt" DESC);
CREATE INDEX IF NOT EXISTS idx_credit_transaction_type ON "CreditTransaction"(type);

-- Subscription indexes
CREATE INDEX IF NOT EXISTS idx_subscription_user_id ON "Subscription"("userId");
CREATE INDEX IF NOT EXISTS idx_subscription_org_id ON "Subscription"("organizationId");
CREATE INDEX IF NOT EXISTS idx_subscription_status ON "Subscription"(status);
CREATE INDEX IF NOT EXISTS idx_subscription_provider_ref ON "Subscription"("providerReference");

-- SyncState indexes
CREATE INDEX IF NOT EXISTS idx_sync_state_repository_id ON "SyncState"("repositoryId");
CREATE INDEX IF NOT EXISTS idx_sync_state_last_synced ON "SyncState"("lastSyncedAt" DESC);

-- AuditLog indexes
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON "AuditLog"("userId");
CREATE INDEX IF NOT EXISTS idx_audit_log_api_project_id ON "AuditLog"("apiProjectId");
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON "AuditLog"("createdAt" DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_level ON "AuditLog"(level);

-- Session indexes
CREATE INDEX IF NOT EXISTS idx_session_user_id ON "Session"("userId");
CREATE INDEX IF NOT EXISTS idx_session_expires ON "Session"(expires);

-- Account indexes
CREATE INDEX IF NOT EXISTS idx_account_user_id ON "Account"("userId");

-- NotificationPreference indexes
CREATE INDEX IF NOT EXISTS idx_notification_user_id ON "NotificationPreference"("userId");
