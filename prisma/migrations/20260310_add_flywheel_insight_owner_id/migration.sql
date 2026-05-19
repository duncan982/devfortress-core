-- Migration: Add ownerId to FlywheelInsight and make apiProjectId optional
-- This allows insights to be generated for standalone honeypots not linked to API projects

-- Make apiProjectId nullable (was NOT NULL in initial migration)
ALTER TABLE "FlywheelInsight" ALTER COLUMN "apiProjectId" DROP NOT NULL;

-- Add ownerId column if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'FlywheelInsight' AND column_name = 'ownerId'
    ) THEN
        ALTER TABLE "FlywheelInsight" ADD COLUMN "ownerId" TEXT;
    END IF;
END $$;

-- Add foreign key constraint if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'FlywheelInsight_ownerId_fkey'
    ) THEN
        ALTER TABLE "FlywheelInsight"
            ADD CONSTRAINT "FlywheelInsight_ownerId_fkey"
            FOREIGN KEY ("ownerId") REFERENCES "User"("id")
            ON DELETE SET NULL ON UPDATE CASCADE;
    END IF;
END $$;

-- Add indexes for performance
CREATE INDEX IF NOT EXISTS "FlywheelInsight_ownerId_idx" ON "FlywheelInsight"("ownerId");
CREATE INDEX IF NOT EXISTS "FlywheelInsight_apiProjectId_idx" ON "FlywheelInsight"("apiProjectId");
