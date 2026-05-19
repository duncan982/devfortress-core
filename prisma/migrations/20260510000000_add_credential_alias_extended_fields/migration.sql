-- AlterTable: add extended fields to CredentialAlias
ALTER TABLE "CredentialAlias" ADD COLUMN IF NOT EXISTS "familyId" TEXT;
ALTER TABLE "CredentialAlias" ADD COLUMN IF NOT EXISTS "maxUses" INTEGER;
ALTER TABLE "CredentialAlias" ADD COLUMN IF NOT EXISTS "bindingIpCidr" TEXT;
ALTER TABLE "CredentialAlias" ADD COLUMN IF NOT EXISTS "bindingRegions" TEXT[];
ALTER TABLE "CredentialAlias" ADD COLUMN IF NOT EXISTS "bindingTimeEnd" TEXT;
ALTER TABLE "CredentialAlias" ADD COLUMN IF NOT EXISTS "bindingTimeStart" TEXT;
ALTER TABLE "CredentialAlias" ADD COLUMN IF NOT EXISTS "bindingTimeZone" TEXT;
ALTER TABLE "CredentialAlias" ADD COLUMN IF NOT EXISTS "bindingWorkloadId" TEXT;
ALTER TABLE "CredentialAlias" ADD COLUMN IF NOT EXISTS "bindingDeviceId" TEXT;
ALTER TABLE "CredentialAlias" ADD COLUMN IF NOT EXISTS "bindingAppBundle" TEXT;
ALTER TABLE "CredentialAlias" ADD COLUMN IF NOT EXISTS "bindingAgentTools" TEXT[];

-- CreateIndex
CREATE INDEX IF NOT EXISTS "CredentialAlias_familyId_idx" ON "CredentialAlias"("familyId");

-- AlterTable: fix licenses columns
ALTER TABLE "licenses" ALTER COLUMN "product_id" SET NOT NULL;
ALTER TABLE "licenses" ALTER COLUMN "purchase_id" SET NOT NULL;
ALTER TABLE "licenses" ALTER COLUMN "created_at" SET DEFAULT CURRENT_TIMESTAMP;

-- DropIndex (old non-Prisma index)
DROP INDEX IF EXISTS "idx_org_member_user_org";
