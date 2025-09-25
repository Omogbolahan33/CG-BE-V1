// src/utils/prisma.ts

import { PrismaClient } from '@prisma/client';

/**
 * Global PrismaClient instance.
 * It's declared globally to prevent hot-reloading from creating new instances
 * in development, which can exhaust database connections.
 * * @see https://www.prisma.io/docs/guides/other/troubleshooting-dev-violations
 */
const prismaClient = new PrismaClient({
  // Optionally add logging configuration here
  // log: ['query', 'info', 'warn', 'error'],
});

// A robust way to ensure we always export the same instance
const prisma = prismaClient;

export default prisma;
