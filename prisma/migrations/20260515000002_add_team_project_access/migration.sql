-- CreateTable
CREATE TABLE "TeamProjectAccess" (
    "id" TEXT NOT NULL,
    "teamId" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "grantedById" TEXT NOT NULL,
    "grantedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "TeamProjectAccess_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "TeamProjectAccess_teamId_projectId_key" ON "TeamProjectAccess"("teamId", "projectId");

-- AddForeignKey
ALTER TABLE "TeamProjectAccess" ADD CONSTRAINT "TeamProjectAccess_teamId_fkey" FOREIGN KEY ("teamId") REFERENCES "Team"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TeamProjectAccess" ADD CONSTRAINT "TeamProjectAccess_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "ApiProject"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TeamProjectAccess" ADD CONSTRAINT "TeamProjectAccess_grantedById_fkey" FOREIGN KEY ("grantedById") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
