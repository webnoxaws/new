// lib/db.ts
import { PrismaClient } from '@prisma/client';
declare global {
  // eslint-disable-next-line no-var
  var prisma: PrismaClient | undefined;
}

const db = global.prisma || new PrismaClient();

export default db;
