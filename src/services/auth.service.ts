// src/services/auth.service.ts

import prisma from '../utils/prisma';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { cleanIdentifier } from '../utils/sanitizer';
import { User, UserRole, BackofficeSettings } from '@prisma/client';

// Define the fields we want to exclude from the public User object
type SensitiveUserFields = 'password' 
  | 'verificationOtp' 
  | 'verificationOtpExpiry' 
  | 'passwordResetOtp' 
  | 'passwordResetOtpExpiry' 
  | 'banReason' // Might be sensitive administrative detail
  | 'banStartDate';


// Define the shape of the login credentials
interface LoginCredentials {
  identifier: string;
  password: string;
}

// Define the expected successful response type
interface LoginResponse {
  user: Omit<User, SensitiveUserFields>; // Exclude password from the returned User object
  token: string;
}

/**
 * Fetches the singleton BackofficeSettings record.
 * @returns The BackofficeSettings record.
 */
const getBackofficeSettings = async (): Promise<BackofficeSettings> => {
    // Best practice for singleton table: find the first (and only) record.
    const settings = await prisma.backofficeSettings.findFirst();
    if (!settings) {
        // Handle case where settings hasn't been created yet (should auto-create on first run)
        throw new Error('Backoffice settings not initialized.');
    }
    return settings;
}

/**
 * Primary business logic for user login.
 * Handles validation, pre-conditions, core logic, and side effects.
 * @param credentials User identifier and password.
 * @returns The user object (without password) and a JWT token.
 */
export const loginUser = async (credentials: LoginCredentials): Promise<LoginResponse> => {
  const { identifier, password } = credentials;
  
  // --- 0. Validation (Empty Check) ---
  if (!identifier || !password) {
    throw Object.assign(new Error('Identifier and password are required.'), { statusCode: 401 });
  }

  // --- 0. Sanitize Identifier ---
  const cleanedIdentifier = cleanIdentifier(identifier).toLowerCase();
  
  // --- 1. Find User by Identifier (username or email) ---
  const user = await prisma.user.findFirst({
    where: {
      OR: [
        { username: cleanedIdentifier },
        { email: cleanedIdentifier },
      ],
    },
  });

  if (!user) {
    throw Object.assign(new Error('Invalid identifier or password.'), { statusCode: 401 });
  }

  const userRole = user.role as UserRole;
  const isAdmin = userRole === UserRole.Admin || userRole === UserRole.SuperAdmin;

  // --- Pre-conditions (Backoffice Settings Check) ---
  const settings = await getBackofficeSettings();
  if (settings.maintenanceMode && !isAdmin) {
    throw Object.assign(new Error('The platform is currently under maintenance.'), { statusCode: 503 });
  }
  if (!settings.enableLogins && !isAdmin) {
    throw Object.assign(new Error('Login is temporarily disabled for Members.'), { statusCode: 403 });
  }


  // --- 2. Secure Password Comparison ---
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    throw Object.assign(new Error('Invalid identifier or password.'), { statusCode: 401 });
  }

  // --- 3. Check Account Status (isActive) ---
  if (!user.isActive) {
    throw Object.assign(new Error('Account is deactivated. Please contact support.'), { statusCode: 403 });
  }

  // --- 4. Check Ban Status (banExpiresAt) ---
  const isBanned = user.banExpiresAt && user.banExpiresAt > new Date();
  if (isBanned) {
    throw Object.assign(new Error(`Account is banned until ${user.banExpiresAt!.toISOString()}.`), { statusCode: 403 });
  }
  
  // --- Side Effect: Update lastSeen (Transactional Integrity) ---
  // Wrap in a transaction to ensure atomic update of lastSeen and log creation.
  const loggedInUser = await prisma.$transaction(async (tx) => {
    // 1. Update lastSeen
    const updatedUser = await tx.user.update({
      where: { id: user.id },
      data: { lastSeen: new Date() },
    });

    // 2. Auditing: Log Successful Login
    await tx.activityLog.create({
      data: {
        userId: user.id,
        action: 'SUCCESSFUL_LOGIN',
        details: `Successful login via identifier: ${cleanedIdentifier}`,
        // Note: IP and User Agent logging is done at the controller/middleware level,
        // as the service layer should be abstracted from network details (req/res objects).
      }
    });
    return updatedUser;
  });


  // --- 5. Generate and Sign JWT (RS256) ---
  // NOTE: In a real environment, you MUST load the private key securely from env/secrets.
  // Using a placeholder for public/private key pair here. 
  // You would use an environment variable like process.env.JWT_PRIVATE_KEY
  const privateKey = 'YOUR_SECRET_RS256_PRIVATE_KEY'; // Placeholder

  const jti = `${user.id}-${Date.now()}`; // Unique JWT ID
  const payload = {
    userId: user.id,
    role: user.role,
    jti: jti,
  };

  const token = jwt.sign(payload, privateKey, {
    algorithm: 'RS256',
    expiresIn: '24h', // 86400 seconds
  });

// Prepare user object for response (excluding sensitive fields)
const { 
  password: _, 
  verificationOtp: __, 
  verificationOtpExpiry: ___, 
  passwordResetOtp: ____, 
  passwordResetOtpExpiry: _____, 
  banReason: ______, 
  banStartDate: _______, 
  ...userWithoutPassword 
} = loggedInUser; // Destructure and omit all sensitive fields

// The userWithoutPassword object is now correctly typed as Omit<User, SensitiveUserFields>
return {
  user: userWithoutPassword,
  token: token,
};
};

/**
 * Auditing: Log Failed Login Attempt.
 * This function should be called by the controller *before* returning the 401/403.
 * @param identifier The identifier used for the attempt.
 * @param ip The source IP address.
 * @param userAgent The User-Agent string.
 */
export const logFailedLogin = async (identifier: string, ip: string, userAgent: string | undefined): Promise<void> => {
    const cleanedIdentifier = cleanIdentifier(identifier);
    await prisma.activityLog.create({
        data: {
            // Log as 'system' if user ID is unknown/not found
            userId: (await prisma.user.findFirst({
              where: { 
                OR: [{ username: cleanedIdentifier.toLowerCase() }, { email: cleanedIdentifier.toLowerCase() }] 
              },
              select: { id: true }
            }))?.id || 'SYSTEM', 
            action: 'FAILED_LOGIN',
            details: `Failed login attempt. Identifier: ${cleanedIdentifier}, IP: ${ip}, User Agent: ${userAgent || 'Unknown'}`,
        }
    });
};
