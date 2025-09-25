import prisma from '../utils/prisma';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import * as crypto from 'crypto';
import { cleanIdentifier } from '../utils/sanitizer';
import { User, UserRole, BackofficeSettings } from '@prisma/client';
import { AuthenticationError } from '../errors/AuthenticationError'; 
import { sendVerificationEmail } from '../utils/emailSender';

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

// Define the shape of the signup credentials
interface SignUpCredentials {
  username: string;
  email: string;
  password: string;
}
// Define the expected successful response type
interface SignUpResponse {
    user: Omit<User, SensitiveUserFields>; 
    token: string;
}
// Define the shape of the verifyEmail credentials
interface VerifyEmailByOtpCredentials {
  userId: string; // Passed from authMiddleware
  otp: string;
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

/**
 * Generates a 6-digit numeric OTP.
 */
const generateOtp = (): string => {
    return crypto.randomInt(100000, 1000000).toString();
};

/**
 * Validates the username format based on the business logic: 
 * alphanumeric, 6-11 characters.
 */
const validateUsername = (username: string): boolean => {
    return /^[a-zA-Z0-9]{6,11}$/.test(username);
};


// --- Main Service Logic ----------------------------------------------

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



// --- Main Service Logic ------------------------------------------------------------------

/**
 * API: Sign Up
 * @description Registers a new user with email verification flow.
 * @param credentials User registration details.
 * @returns The newly created user object (without password) and a JWT token.
 */
export const signUp = async (credentials: SignUpCredentials): Promise<SignUpResponse> => {
    const { username, email, password } = credentials;
    const saltRounds = 10;
    const OTP_EXPIRY_MINUTES = 15;

    // 1. Validation and Sanitization
    if (!username || !email || !password) {
        throw new AuthenticationError('All fields are required.', 400);
    }
    
    const cleanedUsername = cleanIdentifier(username).toLowerCase();
    const cleanedEmail = cleanIdentifier(email).toLowerCase();

    if (!validateUsername(cleanedUsername)) {
        throw new AuthenticationError('Username must be 6-11 alphanumeric characters.', 400);
    }
    if (password.length < 6) {
        throw new AuthenticationError('Password must be at least 6 characters long.', 400);
    }
    
    // 2. Pre-conditions (Backoffice Settings Check)
    const settings = await getBackofficeSettings();
    if (!settings.enableSignups) {
        throw new AuthenticationError('New user registration is currently disabled.', 403);
    }
    
    // 3. Uniqueness Check
    const existingUser = await prisma.user.findFirst({
        where: { OR: [{ username: cleanedUsername }, { email: cleanedEmail }] },
        select: { username: true, email: true }
    });

    if (existingUser) {
        if (existingUser.username?.toLowerCase() === cleanedUsername) {
            throw new AuthenticationError('Username is already taken.', 409);
        }
        if (existingUser.email?.toLowerCase() === cleanedEmail) {
            throw new AuthenticationError('Email is already in use.', 409);
        }
    }

    // 4. Hashing and OTP Generation
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const rawOtp = generateOtp();
    const hashedOtp = await bcrypt.hash(rawOtp, saltRounds); 
    const otpExpiry = new Date();
    otpExpiry.setMinutes(otpExpiry.getMinutes() + OTP_EXPIRY_MINUTES);

    // 5. Create User (Transactional)
    const newUser = await prisma.$transaction(async (tx) => {
        const createdUser = await tx.user.create({
            data: {
                username: cleanedUsername,
                email: cleanedEmail,
                password: hashedPassword,
                role: UserRole.Member,
                isActive: true, 
                isVerified: false, 
                verificationOtp: hashedOtp,
                verificationOtpExpiry: otpExpiry,
            },
        });

        // 6. Side Effect: Send Verification Email
        await sendVerificationEmail(createdUser.email, rawOtp);

        return createdUser;
    });

    // 7. Generate JWT
    const secret = process.env.JWT_SECRET;
    if (!secret) {
        throw new Error('JWT_SECRET not configured in environment variables.');
    }

    const jti = `${newUser.id}-${Date.now()}`;
    const payload = {
        userId: newUser.id,
        role: newUser.role,
        jti: jti,
    };

    const token = jwt.sign(payload, secret, {
        algorithm: 'HS256',
        expiresIn: '24h',
    });

    // 8. Prepare Response
    const {
        password: _, verificationOtp: __, verificationOtpExpiry: ___, 
        passwordResetOtp: ____, passwordResetOtpExpiry: _____, 
        banReason: ______, banStartDate: _______,
        ...userWithoutSensitiveFields
    } = newUser;

    return {
        user: userWithoutSensitiveFields,
        token: token,
    };
};


// --- Main Service Logic ------------------------------------------------------------------

/**
 * API: Verify Email (Authenticated)
 * @description Verifies a user's email address using a time-sensitive OTP,
 * retrieving user data from the provided userId (via JWT).
 * @param credentials User ID and the 6-digit OTP.
 */
export const verifyEmailByOtp = async (credentials: VerifyEmailByOtpCredentials): Promise<{ success: boolean }> => {
    const { userId, otp } = credentials;

    // 1. Find User by ID
    const user = await prisma.user.findUnique({
        where: { id: userId },
    });

    // Should not happen if authMiddleware is correctly implemented, but good for defense
    if (!user) {
        throw new AuthenticationError('Authenticated user not found.', 404);
    }

    // 2. Pre-conditions Check
    if (user.isVerified) {
        throw new AuthenticationError('Account is already verified.', 400);
    }
    if (!user.verificationOtp || !user.verificationOtpExpiry) {
        throw new AuthenticationError('No pending verification found. Request a new code.', 400);
    }

    // 3. OTP Expiry Check
    if (user.verificationOtpExpiry < new Date()) {
        // The error response is sent, but the cleanup is handled by the atomic update below
        throw new AuthenticationError('Verification code has expired. Please request a new one.', 400);
    }

    // 4. OTP Comparison
    const isOtpValid = await bcrypt.compare(otp, user.verificationOtp);
    
    // 5. Atomic Update Transaction
    if (isOtpValid) {
        await prisma.$transaction(async (tx) => {
            // Update the user status and clear OTP fields
            await tx.user.update({
                where: { id: user.id },
                data: {
                    isVerified: true,
                    verificationOtp: null, 
                    verificationOtpExpiry: null,
                }
            });

            // Log activity
            await tx.activityLog.create({
                data: {
                    userId: user.id,
                    action: 'EMAIL_VERIFIED',
                    details: 'User successfully verified email via OTP.',
                }
            });
        });
        
        return { success: true };

    } else {
        // Invalid OTP provided
        throw new AuthenticationError('Invalid verification code.', 400);
    }
};
