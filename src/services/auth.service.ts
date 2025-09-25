import prisma from '../utils/prisma';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { cleanIdentifier } from '../utils/sanitizer';
import { User, UserRole, BackofficeSettings } from '@prisma/client';
import { AuthenticationError } from '../errors/AuthenticationError'; // Assuming you have a custom error class for clarity

// Define the fields we want to exclude from the public User object
type SensitiveUserFields = 'password'
  | 'verificationOtp'
  | 'verificationOtpExpiry'
  | 'passwordResetOtp'
  | 'passwordResetOtpExpiry'
  | 'banReason'
  | 'banStartDate';

// Define the shape of the login credentials
interface LoginCredentials {
  identifier: string;
  password: string;
  // Metadata fields for logging (often passed from the controller)
  ip?: string;
  userAgent?: string;
}

// Define the expected successful response type
interface LoginResponse {
  user: Omit<User, SensitiveUserFields>;
  token: string;
}

// --- Internal Helpers ---

/**
 * Fetches the singleton BackofficeSettings record.
 * @returns The BackofficeSettings record.
 */
const getBackofficeSettings = async (): Promise<BackofficeSettings> => {
    // Best practice for singleton table: find the first (and only) record.
    const settings = await prisma.backofficeSettings.findFirst();
    if (!settings) {
        // In a production environment, this should only happen if seed data is missing.
        throw new Error('Backoffice settings not initialized.');
    }
    return settings;
}

/**
 * Auditing: Log Failed Login Attempt.
 * This function will only create an ActivityLog entry if a user with the identifier exists.
 */
export const logFailedLogin = async (identifier: string, ip: string | undefined, userAgent: string | undefined): Promise<void> => {
    const cleanedIdentifier = cleanIdentifier(identifier);

    // 1. Try to find the user ID based on the identifier
    const userToLog = await prisma.user.findFirst({
        where: {
            OR: [{ username: cleanedIdentifier.toLowerCase() }, { email: cleanedIdentifier.toLowerCase() }]
        },
        select: { id: true }
    });

    // 2. ONLY proceed with logging if a user ID was found, preventing foreign key violation.
    if (!userToLog?.id) {
        return;
    }

    // 3. Log the failure against the existing user's ID
    await prisma.activityLog.create({
        data: {
            userId: userToLog.id, // Now guaranteed to be a valid User ID
            action: 'FAILED_LOGIN',
            details: `Failed login attempt. Identifier: ${cleanedIdentifier}, IP: ${ip || 'Unknown'}, User Agent: ${userAgent || 'Unknown'}`,
        }
    });
};


// --- Main Service Logic ---

/**
 * Primary business logic for user login.
 * Handles validation, pre-conditions, core logic, and side effects.
 * @param credentials User identifier, password, and optional metadata (IP/User Agent).
 * @returns The user object (without password) and a JWT token.
 */
export const loginUser = async (credentials: LoginCredentials): Promise<LoginResponse> => {
    const { identifier, password, ip, userAgent } = credentials;

    // --- 0. Validation (Empty Check) ---
    if (!identifier || !password) {
        throw new AuthenticationError('Identifier and password are required.');
    }

    // --- 0. Sanitize Identifier ---
    const cleanedIdentifier = cleanIdentifier(identifier).toLowerCase();

    // --- 1. Find User by Identifier (username OR email) ---
    const user = await prisma.user.findFirst({
        where: {
            // FIX: Use OR to correctly check both fields
            OR: [
                { username: cleanedIdentifier },
                { email: cleanedIdentifier },
            ],
        },
    });

    // --- 1.1 Handle User Not Found ---
    if (!user) {
        // Log attempt for non-existent user (will be ignored by logFailedLogin now)
        await logFailedLogin(identifier, ip, userAgent);
        // Throw generic error message to prevent enumeration attacks
        throw new AuthenticationError('Invalid identifier or password.');
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
    // FIX: Ensure bcrypt.compare is correctly used to verify the password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
        // Log attempt for existing user with wrong password
        await logFailedLogin(identifier, ip, userAgent);
        throw new AuthenticationError('Invalid identifier or password.');
    }

    // --- 3. Check Account Status (isActive) ---
    if (!user.isActive) {
        throw new AuthenticationError('Account is deactivated. Please contact support.', 403); // Uses 403
    }

    // --- 4. Check Ban Status (banExpiresAt) ---
    const isBanned = user.banExpiresAt && user.banExpiresAt > new Date();
    if (isBanned) {
         throw new AuthenticationError(`Account is banned until ${user.banExpiresAt!.toISOString()}.`, 403); // Uses 403
    }

    // --- Side Effect: Update lastSeen (Transactional Integrity) ---
    const loggedInUser = await prisma.$transaction(async (tx) => {
        // 1. Update lastSeen
        const updatedUser = await tx.user.update({
            where: { id: user.id },
            data: { lastSeen: new Date() },
        });

        // 2. Auditing: Log Successful Login
        await tx.activityLog.create({
            data: {
                userId: user.id, // Valid ID is guaranteed here
                action: 'SUCCESSFUL_LOGIN',
                details: `Successful login via identifier: ${cleanedIdentifier}, IP: ${ip || 'Unknown'}, User Agent: ${userAgent || 'Unknown'}`,
            }
        });
        return updatedUser;
    });


    // --- 5. Generate and Sign JWT (HS256) ---
    // FIX: Switch to HS256 for easy local development and use ENV var
    const secret = process.env.JWT_SECRET;

    if (!secret) {
        throw new Error('JWT_SECRET not configured in environment variables.');
    }

    const jti = `${user.id}-${Date.now()}`; // Unique JWT ID
    const payload = {
        userId: user.id,
        role: user.role,
        jti: jti,
    };

    const token = jwt.sign(payload, secret, {
        algorithm: 'HS256', // Changed from RS256 to HS256
        expiresIn: '24h',
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
    } = loggedInUser;

    return {
        user: userWithoutPassword,
        token: token,
    };
};
