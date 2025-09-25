import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import prisma from '../lib/prisma';
import { ApiError } from '../lib/errors';

interface Credentials {
  identifier: string;
  password: string;
}

export const loginUser = async ({ identifier, password }: Credentials) => {
  if (!identifier || !password) {
    throw new ApiError(400, 'Identifier and password are required');
  }

  // Load BackofficeSettings (singleton row)
  const settings = await prisma.backofficeSettings.findFirst();
  if (!settings) {
    throw new ApiError(500, 'Backoffice settings not configured');
  }

  // Find user by username or email (case-insensitive)
  const user = await prisma.user.findFirst({
    where: {
      OR: [
        { username: { equals: identifier, mode: 'insensitive' } },
        { email: { equals: identifier, mode: 'insensitive' } },
      ],
    },
  });

  if (!user) {
    throw new ApiError(401, 'Invalid credentials');
  }

  // Pre-conditions: enableLogins + maintenanceMode
  const privileged = ['Admin', 'Super Admin'].includes(user.role);

  if (!settings.enableLogins && !privileged) {
    throw new ApiError(403, 'Logins are currently disabled');
  }

  if (settings.maintenanceMode && !privileged) {
    throw new ApiError(503, 'Service is under maintenance');
  }

  // Validate password
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    throw new ApiError(401, 'Invalid credentials');
  }

  // Check if active
  if (!user.isActive) {
    throw new ApiError(403, 'User account is inactive');
  }

  // Check if banned
  if (user.banExpiresAt && user.banExpiresAt > new Date()) {
    throw new ApiError(403, 'User is currently banned');
  }

  // Update lastSeen
  await prisma.user.update({
    where: { id: user.id },
    data: { lastSeen: new Date() },
  });

  // Generate JWT
  const jti = uuidv4();
  const token = jwt.sign(
    {
      userId: user.id,
      role: user.role,
      jti,
    },
    process.env.JWT_SECRET!,
    { expiresIn: '1d' }
  );

  return { user, token };
};
