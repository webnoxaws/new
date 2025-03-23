/*
  Warnings:

  - You are about to drop the column `bankAccountDetails` on the `SellerProfile` table. All the data in the column will be lost.
  - A unique constraint covering the columns `[bankAccountId]` on the table `SellerProfile` will be added. If there are existing duplicate values, this will fail.

*/
-- AlterTable
ALTER TABLE "SellerProfile" DROP COLUMN "bankAccountDetails",
ADD COLUMN     "bankAccountId" TEXT;

-- CreateTable
CREATE TABLE "BankAccountDetails" (
    "id" TEXT NOT NULL,
    "accountHolderName" TEXT NOT NULL,
    "accountNumber" TEXT NOT NULL,
    "bankName" TEXT NOT NULL,
    "ifscCode" TEXT NOT NULL,
    "branchName" TEXT,
    "accountType" TEXT,
    "isVerified" BOOLEAN NOT NULL DEFAULT false,
    "verificationDate" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "BankAccountDetails_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "BankAccountDetails_accountNumber_idx" ON "BankAccountDetails"("accountNumber");

-- CreateIndex
CREATE INDEX "BankAccountDetails_ifscCode_idx" ON "BankAccountDetails"("ifscCode");

-- CreateIndex
CREATE UNIQUE INDEX "SellerProfile_bankAccountId_key" ON "SellerProfile"("bankAccountId");

-- AddForeignKey
ALTER TABLE "SellerProfile" ADD CONSTRAINT "SellerProfile_bankAccountId_fkey" FOREIGN KEY ("bankAccountId") REFERENCES "BankAccountDetails"("id") ON DELETE SET NULL ON UPDATE CASCADE;
