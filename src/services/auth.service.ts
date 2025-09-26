import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import * as crypto from 'crypto';
    //Prisma instances
import prisma from '../utils/prisma';
import { UserRole, BackofficeSettings } from '@prisma/client';
import type {  User, SensitiveUserFields, PrivateUserFields, PublicUserProfile, NotificationType } from '../types';
  //Error handlers
import { AuthenticationError } from '../errors/AuthenticationError'; 
import { BadRequestError } from '../errors/BadRequestError'; 
import { NotFoundError } from '../errors/NotFoundError';
import { ConflictError } from '../errors/ConflictError'; 
import { ForbiddenError } from '../errors/ForbiddenError'; 
  //Utility functions
import { cleanIdentifier } from '../utils/sanitizer';
import { encryptData } from '../utils/crypto.util';
import { emitWebSocketEvent } from '../utils/ws.util'; 
import { sendVerificationEmail } from '../utils/emailSender';



interface UpdateBankAccountPayload {
  password: string; // For re-authentication
  accountName: string;
  accountNumber: string;
  bankName: string;
  // Add other required BankAccount fields
}

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
  userId: string;
  otp: string;
}

// Define the shape of the ResetPassword credentials
interface ResetPasswordCredentials {
  email: string;
  otp: string;
  newPassword: string;
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


// ----------------------------------- Main Service Logic ------------------------------------------------------------------



/**
 * API: Resend Verification OTP
 * @description Generates and sends a new verification OTP to the authenticated user.
 * @param userId The ID of the logged-in user (from the JWT).
 */
export const resendVerificationOtp = async (userId: string): Promise<{ success: boolean }> => {
    const saltRounds = 10;
    const OTP_EXPIRY_MINUTES = 15;

    // 1. Find User and Check Pre-conditions
    const user = await prisma.user.findUnique({
        where: { id: userId },
    });

    if (!user) {
        throw new AuthenticationError('Authenticated user not found.', 404);
    }

    if (user.isVerified) {
        throw new AuthenticationError('Account is already verified.', 400);
    }
    
    // NOTE: Rate limiting logic (e.g., lastOtpSentAt check) should ideally be performed here 
    // or by a dedicated middleware/cache to prevent database load.

    // 2. Core Logic: Hashing and OTP Generation
    const rawOtp = generateOtp(); // Reusing the helper from signUp
    const hashedOtp = await bcrypt.hash(rawOtp, saltRounds); 
    const otpExpiry = new Date();
    otpExpiry.setMinutes(otpExpiry.getMinutes() + OTP_EXPIRY_MINUTES);

    // 3. Update User Record
    await prisma.$transaction(async (tx) => {
        // Update the user status with the new OTP details
        await tx.user.update({
            where: { id: user.id },
            data: {
                verificationOtp: hashedOtp,
                verificationOtpExpiry: otpExpiry,
                // Add a field for rate limiting if you have one (e.g., lastOtpSentAt: new Date())
            }
        });

        // 4. Side Effect: Send Email
        await sendVerificationEmail(user.email, rawOtp);

        // 5. Auditing
        await tx.activityLog.create({
            data: {
                userId: user.id,
                action: 'RESEND_OTP',
                details: 'New verification OTP generated and sent.',
            }
        });
    });
    
    return { success: true };
};


// ----------------------------------- Main Service Logic ------------------------------------------------------------------


/**
 * API: Request Password Reset
 * @description Initiates the password reset process by generating and sending an OTP.
 * @param email The user's email address.
 * @returns Always returns { success: true } to prevent email enumeration.
 */
export const requestPasswordReset = async (email: string): Promise<{ success: boolean }> => {
    const saltRounds = 10;
    const OTP_EXPIRY_MINUTES = 15;

    // 1. Sanitize and Find User (Case-insensitive)
    const cleanedEmail = cleanIdentifier(email).toLowerCase();

    // We do NOT use findUnique here because we want to avoid throwing on not found.
    const user = await prisma.user.findFirst({
        where: { email: cleanedEmail },
    });

    // 2. Core Logic: Only proceed if user is found
    if (user) {
        // NOTE: This is where rate-limiting logic would be applied (e.g., checking Redis or a timestamp in the DB)
        
        // a. Generate and Hash OTP
        const rawOtp = generateOtp(); // Reusing the 6-digit helper
        const hashedOtp = await bcrypt.hash(rawOtp, saltRounds); 
        const otpExpiry = new Date();
        otpExpiry.setMinutes(otpExpiry.getMinutes() + OTP_EXPIRY_MINUTES);

        // b. Update User Record (Atomic Transaction)
        await prisma.$transaction(async (tx) => {
            await tx.user.update({
                where: { id: user.id },
                data: {
                    passwordResetOtp: hashedOtp,
                    passwordResetOtpExpiry: otpExpiry,
                }
            });

            // c. Side Effect: Send Email
            // NOTE: You'll need a new stub for this, or update your emailSender utility.
            // For now, we'll log it using a generic sender stub.
            await sendPasswordResetEmail(user.email, rawOtp);
            
            // d. Auditing
            await tx.activityLog.create({
                data: {
                    userId: user.id,
                    action: 'PASSWORD_RESET_REQUEST',
                    details: 'Password reset OTP generated and sent.',
                }
            });
        });
    }

    // 3. Security Note: Always return success to prevent email enumeration attacks.
    return { success: true };
};

// NOTE: You need this new stub function in your email utility
/**
 * STUB: Simulates sending a password reset email.
 */
export const sendPasswordResetEmail = async (email: string, otp: string): Promise<void> => {
    console.log(`EMAIL STUB: Sent password reset code ${otp} to ${email}`);
    return Promise.resolve();
};



// ----------------------------------- Main Service Logic ------------------------------------------------------------------



/**
 * API: Reset Password
 * @description Sets a new password for the user after verifying the OTP.
 * @param data Email, OTP, and the new password.
 * @returns { success: true } if the password was successfully reset.
 */
export const resetPassword = async (data: ResetPasswordCredentials): Promise<{ success: boolean }> => {
    const { email, otp, newPassword } = data;
    const saltRounds = 10;
    const cleanedEmail = cleanIdentifier(email).toLowerCase();

    // 1. Validation: New Password Strength
    if (newPassword.length < 6) {
        throw new AuthenticationError('New password must be at least 6 characters long.', 400);
    }
    
    // 2. Find User by Email
    const user = await prisma.user.findFirst({
        where: { email: cleanedEmail },
    });

    if (!user) {
        // Return a generic error to avoid confirming non-existent emails, 
        // though the error code is 400 as per specification for "invalid credentials"
        throw new AuthenticationError('Invalid email, OTP, or weak password.', 400);
    }

    // 3. Pre-conditions & Expiry Check
    if (!user.passwordResetOtp || !user.passwordResetOtpExpiry) {
        throw new AuthenticationError('Invalid email, OTP, or weak password.', 400);
    }
    
    if (user.passwordResetOtpExpiry < new Date()) {
        // Clear expired OTP fields (fire-and-forget, safety cleanup)
        await prisma.user.update({
            where: { id: user.id },
            data: { passwordResetOtp: null, passwordResetOtpExpiry: null },
        });
        throw new AuthenticationError('Password reset code has expired.', 400);
    }

    // 4. OTP Comparison
    const isOtpValid = await bcrypt.compare(otp, user.passwordResetOtp);

    if (!isOtpValid) {
        throw new AuthenticationError('Invalid password reset code.', 400);
    }

    // 5. Core Logic: Hash New Password
    const newHashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // 6. Atomic Update Transaction
    await prisma.$transaction(async (tx) => {
        // a. Update the user's password
        await tx.user.update({
            where: { id: user.id },
            data: {
                password: newHashedPassword,
                // b. Atomically clear the OTP fields
                passwordResetOtp: null, 
                passwordResetOtpExpiry: null,
            }
        });

        // c. Auditing
        await tx.activityLog.create({
            data: {
                userId: user.id,
                action: 'PASSWORD_RESET_SUCCESS',
                details: 'Password successfully reset via OTP flow.',
            }
        });
    });

    return { success: true };
};


// ----------------------------------- Main Service Logic ------------------------------------------------------------------


/**
 * STUB: Simulates adding a JWT identifier (jti) to a server-side blocklist (e.g., Redis).
 * @param jti The JWT ID to block.
 * @param tokenExpirySeconds The time until the token would naturally expire.
 */
const blockJwt = async (jti: string, tokenExpirySeconds: number): Promise<void> => {
    // In a real application, this would be:
    // await redisClient.set(`blocked:${jti}`, '1', 'EX', tokenExpirySeconds);
    console.log(`SECURITY: JWT ID ${jti} blocked for ${tokenExpirySeconds} seconds.`);
    return Promise.resolve();
};


// ----------------------------------- Main Service Logic ------------------------------------------------------------------

/**
 * API: Sign Out
 * @description Implements server-side logout by invalidating the current JWT.
 * @param token The raw JWT string from the request.
 * @param userId The ID of the logged-in user.
 */
export const signOut = async (token: string, userId: string): Promise<{ success: boolean }> => {
    // 1. Decode the JWT to get the JTI and Expiry
    const decodedToken = jwt.decode(token, { complete: true }) as { header: any, payload: jwt.JwtPayload };
    const jti = decodedToken.payload.jti;
    const exp = decodedToken.payload.exp;

    if (!jti || !exp) {
        // If JTI or EXP are missing (which shouldn't happen if token generation is correct)
        throw new AuthenticationError('Invalid token structure for logout.', 400);
    }
    
    // 2. Calculate remaining time for blocklist TTL (Time-To-Live)
    const nowInSeconds = Math.floor(Date.now() / 1000);
    const timeRemaining = exp - nowInSeconds;
    
    if (timeRemaining > 0) {
        // 3. Block the JWT identifier (Server-side Invalidaton)
        await blockJwt(jti, timeRemaining);
    }

    // 4. Auditing
    await prisma.activityLog.create({
        data: {
            userId: userId,
            action: 'USER_SIGNOUT',
            details: `User successfully signed out. JWT ID ${jti} blocked for ${timeRemaining} seconds.`,
        }
    });

    // Success response
    return { success: true };
};



// ----------------------------------- Main Service Logic ------------------------------------------------------------------


/**
 * API: Get Current User
 * @description Fetches the complete, non-sensitive data for the currently authenticated user.
 * @param userId The ID of the logged-in user (from the JWT).
 * @returns The user object with sensitive fields removed.
 */
export const getCurrentUser = async (userId: string): Promise<Omit<User, SensitiveUserFields>> => {

    const user = await prisma.user.findUnique({
        where: { id: userId },
    });

    if (!user) {
        // This case should be prevented by authMiddleware, but is a safeguard.
        throw new AuthenticationError('Authenticated user record not found.', 404);
    }

    // Explicitly exclude sensitive fields before returning
    const {
        password: _, verificationOtp: __, verificationOtpExpiry: ___, 
        passwordResetOtp: ____, passwordResetOtpExpiry: _____, 
        banReason: ______, banStartDate: _______,
        ...userWithoutSensitiveFields
    } = user;

    return userWithoutSensitiveFields;
};




// ----------------------------------- Main Service Logic ------------------------------------------------------------------


/**
 * API: Get User Profile
 * @description Fetches the public profile data for any user by ID.
 * @param userId The ID of the user whose profile is requested.
 * @returns The public-safe user profile object.
 */
export const getUserProfile = async (userId: string): Promise<PublicUserProfile> => {

    // 1. Find User by ID
    const user = await prisma.user.findUnique({
        where: { id: userId },
        // IMPORTANT: Use select to only query fields you might need for the Public Profile.
        // This is more efficient and safer than querying all fields.
        // We'll query all fields for now to simplify, but a real app should use 'select'.
    });

    if (!user) {
        throw new NotFoundError(`User with ID ${userId} not found.`, 404);
    }

    // 2. Data Exclusion: Explicitly exclude sensitive fields before returning
    const {
        password: _, 
        email: __, 
        address: ___, 
        city: ____, 
        zipCode: _____, 
        //bankAccount: ______, // BankAccount is a relation, so it will be undefined or null here if not explicitly included in the query.
        verificationOtp: _______, 
        verificationOtpExpiry: ________, 
        passwordResetOtp: _________, 
        passwordResetOtpExpiry: __________,
        ...publicProfile
    } = user;
    
    // Note: The 'bankAccount' field is a relation (BankAccounts is another model). 
    // If you don't use `include: { bankAccount: true }` in the query, it will be excluded 
    // automatically by Prisma, but it must be included in the destructuring list for type safety 
    // if you use `Omit` in your type definition.

    return publicProfile as PublicUserProfile;
};


// ----------------------------------- Main Service Logic ------------------------------------------------------------------


/**
 * API: Update User Settings
 * @description Updates the settings for the current user, handling re-hashing,
 * uniqueness checks, and re-verification upon email change.
 * @param userId The ID of the authenticated user.
 * @param settingsData The partial user data to update.
 * @returns The updated user object with sensitive fields excluded.
 */
export const updateUserSettings = async (userId: string, settingsData: Partial<User>): Promise<Omit<User, SensitiveUserFields>> => {
    const saltRounds = 10;
    const OTP_EXPIRY_MINUTES = 15;
    const updatePayload: Partial<User> = {};
    
    // 1. Find Current User for comparison
    const currentUser = await prisma.user.findUnique({
        where: { id: userId },
    });

    if (!currentUser) {
        // Should be caught by authMiddleware, but a safeguard.
        throw new AuthenticationError('Authenticated user not found.', 404);
    }
    
    // 2. Conditional Updates and Validation

    // --- A. Password Change ---
    if (settingsData.password && settingsData.password !== currentUser.password) {
        if (settingsData.password.length < 6) { // Weak password check
            throw new BadRequestError('New password must be at least 6 characters long.', 400);
        }
        updatePayload.password = await bcrypt.hash(settingsData.password, saltRounds);
    }

    // --- B. Username Change ---
    if (settingsData.username && settingsData.username.toLowerCase() !== currentUser.username.toLowerCase()) {
        const cleanedUsername = cleanIdentifier(settingsData.username);
        
        // Uniqueness check (case-insensitive)
        const existingUser = await prisma.user.findFirst({
            where: { username: { equals: cleanedUsername, mode: 'insensitive' } },
        });

        if (existingUser) {
            // Assuming ConflictError is defined for 409 status code
            throw new ConflictError('Username is already taken.', 409);
        }
        updatePayload.username = cleanedUsername;
    }
    
    // --- C. Email Change (Most Complex) ---
    if (settingsData.email && settingsData.email.toLowerCase() !== currentUser.email.toLowerCase()) {
        const cleanedEmail = cleanIdentifier(settingsData.email).toLowerCase();

        // Uniqueness check (case-insensitive)
        const existingEmailUser = await prisma.user.findFirst({
            where: { email: cleanedEmail },
        });
        
        if (existingEmailUser) {
            throw new ConflictError('Email address is already registered.', 409);
        }

        // Action 1: Set new email
        updatePayload.email = cleanedEmail;
        
        // Action 2: Reset verification status
        updatePayload.isVerified = false; 
        
        // Action 3: Generate, Hash, and Store New OTP
        const rawOtp = generateOtp();
        const hashedOtp = await bcrypt.hash(rawOtp, saltRounds); 
        const otpExpiry = new Date();
        otpExpiry.setMinutes(otpExpiry.getMinutes() + OTP_EXPIRY_MINUTES);
        
        updatePayload.verificationOtp = hashedOtp;
        updatePayload.verificationOtpExpiry = otpExpiry;

        // Action 4 (Side Effect): Send verification email to the new address
        await sendVerificationEmail(cleanedEmail, rawOtp);
    }
    
    // --- D. General Field Updates ---
    // Copy all other fields that are valid to update (e.g., avatarUrl, name, etc.)
    // We explicitly avoid iterating over the security/identity fields we already checked.
    const nonSensitiveUpdateKeys = ['name', 'avatarUrl', 'address', 'city', 'zipCode'] as const;

    for (const key of nonSensitiveUpdateKeys) {
        if (settingsData[key] !== undefined) {
            updatePayload[key] = settingsData[key];
        }
    }


    // 3. Final Update and Auditing
    if (Object.keys(updatePayload).length === 0) {
        // Nothing to update
        return currentUser as Omit<User, SensitiveUserFields>;
    }
    
    const updatedUser = await prisma.$transaction(async (tx) => {
        const result = await tx.user.update({
            where: { id: userId },
            data: updatePayload,
        });
        
        // Auditing
        await tx.activityLog.create({
            data: {
                userId: userId,
                action: 'USER_SETTINGS_UPDATE',
                details: `Updated fields: ${Object.keys(updatePayload).join(', ')}`,
            }
        });
        return result;
    });

    // 4. Prepare Response (Excluding sensitive fields)
    const {
        password: _, verificationOtp: __, verificationOtpExpiry: ___, 
        passwordResetOtp: ____, passwordResetOtpExpiry: _____, 
        banReason: ______, banStartDate: _______,
        ...userWithoutSensitiveFields
    } = updatedUser;

    return userWithoutSensitiveFields;
};


// ----------------------------------- Main Service Logic ------------------------------------------------------------------


/**
 * API: Update User Bank Account
 * @description Adds or updates a user's payout bank account with re-authentication and encryption.
 * @param userId The ID of the authenticated user.
 * @param payload The bank account data and the current password.
 * @returns The updated user object with sensitive fields (like bank details) excluded.
 */
export const updateUserBankAccount = async (userId: string, payload: UpdateBankAccountPayload): Promise<Omit<User, SensitiveUserFields>> => {
    const { password, accountName, accountNumber, bankName, ...otherData } = payload;
    
    // 1. Re-authentication Check (Security Requirement)
    const user = await prisma.user.findUnique({
        where: { id: userId },
    });

    if (!user) {
        throw new AuthenticationError('User not found or session invalid.', 401);
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        // Use a generic error message for security
        throw new AuthenticationError('Password confirmation failed. Please enter your current password.', 401);
    }

    // 2. Encryption (Security Requirement)
    const encryptedAccountName = encryptData(accountName);
    const encryptedAccountNumber = encryptData(accountNumber);
    const encryptedBankName = encryptData(bankName);
    
    // 3. Upsert/Update BankAccount (Transactional)
    const updatedUser = await prisma.$transaction(async (tx) => {
        // Check if a bank account already exists for this user
        const existingBankAccount = await tx.bankAccounts.findFirst({
            where: { userId: user.id },
        });

        const bankAccountData = {
            accountName: encryptedAccountName,
            accountNumber: encryptedAccountNumber,
            bankName: encryptedBankName,
            // Spread any other BankAccount fields from payload
            ...otherData, 
        };

        if (existingBankAccount) {
            // Update the existing record
            await tx.bankAccounts.update({
                where: { id: existingBankAccount.id },
                data: bankAccountData,
            });
        } else {
            // Create a new record and link it to the user
            await tx.bankAccounts.create({
                data: {
                    ...bankAccountData,
                    userId: user.id,
                }
            });
        }
        
        // Auditing
        await tx.activityLog.create({
            data: {
                userId: user.id,
                action: 'BANK_ACCOUNT_UPDATE',
                details: 'User bank account information successfully added/updated.',
            }
        });

        // Return the updated user record (to get fresh data)
        return tx.user.findUniqueOrThrow({
            where: { id: userId },
        });
    });

    // 4. Prepare Response (Exclude sensitive fields, including bankAccount relations)
    const {
        password: _, verificationOtp: __, verificationOtpExpiry: ___, 
        passwordResetOtp: ____, passwordResetOtpExpiry: _____, 
        banReason: ______, banStartDate: _______,
        ...userWithoutSensitiveFields
    } = updatedUser;

    return userWithoutSensitiveFields;
};


// ----------------------------------- Main Service Logic ------------------------------------------------------------------


/**
 * API: Request Follow
 * @description Sends a follow request to another user, handling all pre-conditions.
 * @param currentUserId The ID of the authenticated user (the follower).
 * @param targetUserId The ID of the user being followed.
 * @returns { success: boolean }
 */
export const requestFollow = async (currentUserId: string, targetUserId: string): Promise<{ success: boolean }> => {
    
    // --- 1. Pre-conditions Check & Data Fetch ---
    
    // Fetch all necessary data in one transaction/query batch for efficiency
    const [currentUser, targetUser, settings] = await prisma.$transaction([
        // Fetch current user's role and blocked list
        prisma.user.findUnique({
            where: { id: currentUserId },
            select: { id: true, role: true, username: true, blockedUserIds: true }
        }),
        // Fetch target user's follower info and blocked list
        prisma.user.findUnique({
            where: { id: targetUserId },
            select: { 
                followedBy: { select: { id: true } }, // Select IDs for checking
                pendingFollowerIds: true, 
                blockedUserIds: true 
            }
        }),
        // Fetch Backoffice settings (assuming only one settings record exists)
        prisma.backofficeSettings.findFirst({
            where: { id: { not: undefined } } // Find the single settings record
        })
    ]);

    if (!currentUser) {
        throw new NotFoundError("Current user not found.", 404);
    }
    if (!targetUser) {
        throw new NotFoundError(`User with ID ${targetUserId} not found.`, 404);
    }
    if (!settings) {
        // Essential configuration missing
        throw new ForbiddenError("System configuration error. Cannot process request.", 403);
    }

    // 1.1 Current user cannot follow themselves.
    if (currentUserId === targetUserId) {
        throw new BadRequestError("You cannot follow yourself.", 400);
    }
    
    // 1.2 Backoffice setting check (Authorization/Forbidden)
    if (currentUser.role === 'Member' && !settings.enableFollowing) {
        throw new ForbiddenError("Following feature is currently disabled.", 403);
    }
    
    // 1.3 Current user must not already be following the target user.
    const isAlreadyFollowing = targetUser.followedBy.some(f => f.id === currentUserId);
    if (isAlreadyFollowing) {
        throw new BadRequestError("You are already following this user.", 400);
    }

    // 1.4 A follow request must not already be pending.
    if (targetUser.pendingFollowerIds.includes(currentUserId)) {
        throw new BadRequestError("A follow request is already pending.", 400);
    }
    
    // 1.5 Neither user can have blocked the other.
    const isTargetBlockedByCurrent = currentUser.blockedUserIds.includes(targetUserId); 
    const isCurrentBlockedByTarget = targetUser.blockedUserIds.includes(currentUserId);
    
    if (isTargetBlockedByCurrent || isCurrentBlockedByTarget) {
        throw new ForbiddenError("You cannot follow this user due to a block.", 403);
    }

    // --- 2. Core Logic & Side Effects (Atomic Transaction) ---

    await prisma.$transaction(async (tx) => {
        // 2.1 Core Logic: Atomically add currentUserId to the target user's pending list
        await tx.user.update({
            where: { id: targetUserId },
            data: {
                pendingFollowerIds: { push: currentUserId },
            }
        });

        // 2.2 Side Effect: Create Notification (CORRECTED TYPE USAGE)
        const notification: Notification = await tx.notification.create({
            data: {
                userId: targetUserId,      // User receiving the notification
                actorId: currentUserId,    // User who performed the action
                
                // CORRECTED: Using the enum value directly
                type: 'follow_request' as NotificationType, 
                
                content: `${currentUser.username} wants to follow you.`,
                link: `/profile/${currentUser.id}/requests`, // Link to where follow requests are managed
            }
        });

        // 2.3 Realtime Event (Outside of DB transaction for non-blocking IO)
        // We ensure the transaction completes before emitting the event.
        // NOTE: We pass the created Notification object itself in the payload.
        emitWebSocketEvent(`user:${targetUserId}`, { type: 'newNotification', data: notification });
    });


    return { success: true };
};
