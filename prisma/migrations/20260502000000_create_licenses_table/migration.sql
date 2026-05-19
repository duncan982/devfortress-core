-- CreateTable
CREATE TABLE "licenses" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "email" TEXT NOT NULL,
    "product_id" TEXT NOT NULL,
    "purchase_id" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "licenses_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "licenses_email_key" ON "licenses"("email");

-- Enable Row Level Security
ALTER TABLE "licenses" ENABLE ROW LEVEL SECURITY;

-- Policy for Service Roles
CREATE POLICY "Service role has full access to licenses" ON "licenses" 
    USING (auth.role() = 'service_role' OR auth.role() = 'postgres');

-- Policy for Users (allow read if email matches)
CREATE POLICY "Users can view own licenses" ON "licenses" FOR SELECT 
    USING (auth.jwt() ->> 'email' = email);
