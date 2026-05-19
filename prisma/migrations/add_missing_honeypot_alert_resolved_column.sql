-- Add missing resolved column to HoneypotAlert table
-- This fixes the error: The column `HoneypotAlert.resolved` does not exist in the current database

-- Check if the column already exists before adding
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_name = 'HoneypotAlert' 
        AND column_name = 'resolved'
    ) THEN
        -- Add the resolved column with default value false
        ALTER TABLE "HoneypotAlert" 
        ADD COLUMN "resolved" BOOLEAN NOT NULL DEFAULT false;
        
        -- Add resolvedAt column if it doesn't exist
        IF NOT EXISTS (
            SELECT 1 
            FROM information_schema.columns 
            WHERE table_name = 'HoneypotAlert' 
            AND column_name = 'resolvedAt'
        ) THEN
            ALTER TABLE "HoneypotAlert" 
            ADD COLUMN "resolvedAt" TIMESTAMP(3);
        END IF;
        
        -- Add resolution column if it doesn't exist
        IF NOT EXISTS (
            SELECT 1 
            FROM information_schema.columns 
            WHERE table_name = 'HoneypotAlert' 
            AND column_name = 'resolution'
        ) THEN
            ALTER TABLE "HoneypotAlert" 
            ADD COLUMN "resolution" TEXT;
        END IF;
        
        -- Create index for better query performance
        CREATE INDEX IF NOT EXISTS "HoneypotAlert_honeypotId_resolved_idx" 
        ON "HoneypotAlert"("honeypotId", "resolved");
        
        RAISE NOTICE 'Successfully added resolved, resolvedAt, and resolution columns to HoneypotAlert table';
    ELSE
        RAISE NOTICE 'Column resolved already exists in HoneypotAlert table';
    END IF;
END $$;
