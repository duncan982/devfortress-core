-- CreateTable
CREATE TABLE "BlogSchedule" (
    "id" TEXT NOT NULL,
    "postSlug" TEXT NOT NULL,
    "scheduledDate" TIMESTAMP(3) NOT NULL,
    "revealed" BOOLEAN NOT NULL DEFAULT false,
    "notified48h" BOOLEAN NOT NULL DEFAULT false,
    "notifiedDay0" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "BlogSchedule_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "BlogSchedule_postSlug_key" ON "BlogSchedule"("postSlug");

-- AlterEnum
ALTER TYPE "NotificationType" ADD VALUE 'BLOG_SCHEDULE';
