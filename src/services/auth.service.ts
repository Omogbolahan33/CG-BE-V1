import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import * as crypto from 'crypto';
    //Prisma instances
import prisma from '../utils/prisma';
import { UserRole, BackofficeSettings } from '@prisma/client';
import type {  User, 
             SensitiveUserFields, 
             PrivateUserFields, 
             PublicUserProfile, 
             NotificationType, 
             UpdateBankAccountPayload, 
             LoginCredentials, 
             LoginResponse,
             SignUpCredentials,
             SignUpResponse,
             VerifyEmailByOtpCredentials,
             ResetPasswordCredentials, 
             Review, 
             Transaction, 
             AddReviewPayload} from '../types';
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
        const existingBankAccount = await tx.bankAccount.findFirst({
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
            await tx.bankAccount.update({
                where: { id: existingBankAccount.id },
                data: bankAccountData,
            });
        } else {
            // Create a new record and link it to the user
            await tx.bankAccount.create({
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
 * @description Sends a follow request to another user, handling all pre-conditions and side effects.
 * @param currentUserId The ID of the authenticated user (the follower).
 * @param targetUserId The ID of the user being followed.
 * @returns { success: boolean }
 */
export const requestFollow = async (currentUserId: string, targetUserId: string): Promise<{ success: boolean }> => {
    
    // --- 1. Data Fetch & Pre-conditions Check ---

    // Fetch all necessary data: target user's relations, current user's role, and Backoffice settings.
    const [currentUserCheck, targetUserCheck, settings] = await prisma.$transaction([
        // Current User: Role, and WHO they have blocked
        prisma.user.findUnique({
            where: { id: currentUserId },
            select: { 
                id: true, 
                role: true, 
                username: true, 
                blockedUsers: { select: { id: true } }, // Block Check 1
                following: { where: { id: targetUserId }, select: { id: true } }, // Following Check
                pendingFollowing: { where: { id: targetUserId }, select: { id: true } } // Pending Check (if using pendingFollowing instead of pendingFollowerIds)
            }
        }),
        // Target User: WHO has blocked them, and WHO is currently requesting to follow them
        prisma.user.findUnique({
            where: { id: targetUserId },
            select: { 
                blockedBy: { select: { id: true } }, // Block Check 2
                pendingFollowers: { where: { id: currentUserId }, select: { id: true } } // Pending Check
            }
        }),
        // Backoffice Settings: Assuming only one settings record exists
        prisma.backofficeSettings.findFirst({})
    ]);

    if (!currentUserCheck || !targetUserCheck) {
        throw new NotFoundError("User not found.", 404);
    }
    if (!settings) {
        throw new ForbiddenError("System configuration error. Following is disabled.", 403);
    }

    const targetUser = targetUserCheck; // Rename for clarity
    const currentUser = currentUserCheck; 

    // 1.1 Current user cannot follow themselves.
    if (currentUserId === targetUserId) {
        throw new BadRequestError("You cannot follow yourself.", 400);
    }
    
    // 1.2 Backoffice setting check
    if (currentUser.role === 'Member' && !settings.enableFollowing) {
        throw new ForbiddenError("Following feature is currently disabled.", 403);
    }
    
    // 1.3 Current user must not already be following the target user. (Check 'following' relation)
    if (currentUser.following.length > 0) {
        throw new BadRequestError("You are already following this user.", 400);
    }

    // 1.4 A follow request must not already be pending.
    // Check 1: Has the current user already sent a request? (via pendingFollowing)
    // Check 2: Has the target user already received a request from the current user? (via pendingFollowers)
    if (currentUser.pendingFollowing.length > 0 || targetUser.pendingFollowers.length > 0) {
        throw new BadRequestError("A follow request is already pending.", 400);
    }
    
    // 1.5 Neither user can have blocked the other. (Relational Check)
    const isTargetBlockedByCurrent = currentUser.blockedUsers.length > 0;
    const isCurrentBlockedByTarget = targetUser.blockedBy.length > 0;
    
    if (isTargetBlockedByCurrent || isCurrentBlockedByTarget) {
        throw new ForbiddenError("You cannot follow this user due to a block.", 403);
    }

    // --- 2. Core Logic & Side Effects (Atomic Transaction) ---

    await prisma.$transaction(async (tx) => {
        // 2.1 Core Logic: Atomically add the current user to the target user's PENDING FOLLOWERS list.
        // Prisma update syntax for M:N relations: connect the follower (current user) to the pendingFollowing list of the target.
        await tx.user.update({
            where: { id: targetUserId },
            data: {
                pendingFollowers: {
                    connect: { id: currentUserId },
                },
            },
        });

        // 2.2 Side Effect: Create Notification
        const notification = await tx.notification.create({
            data: {
                userId: targetUserId,      // User receiving the notification
                actorId: currentUserId,    // User who sent the request
                type: 'follow_request' as NotificationType, 
                content: `${currentUser.username} wants to follow you.`,
                link: `/profile/${currentUser.id}/requests`, 
            }
        });

        // 2.3 Realtime Event (Outside of DB transaction for non-blocking IO)
        emitWebSocketEvent(`user:${targetUserId}`, { type: 'newNotification', data: notification });
    });


    return { success: true };
};





// ----------------------------------- Main Service Logic ------------------------------------------------------------------


/**
 * API: Cancel Follow Request
 * @description Cancels a follow request sent by the current user to the target user.
 * @param currentUserId The ID of the authenticated user (the one who sent the request).
 * @param targetUserId The ID of the user who received the request.
 * @returns { success: boolean }
 */
export const cancelFollowRequest = async (currentUserId: string, targetUserId: string): Promise<{ success: boolean }> => {
    
    // 1. Pre-check: Ensure the target user exists
    const targetUser = await prisma.user.findUnique({
        where: { id: targetUserId },
        select: { id: true }
    });

    if (!targetUser) {
        throw new NotFoundError(`User with ID ${targetUserId} not found.`, 404);
    }

    // 2. Core Logic: Atomically disconnect the follower from the target user's PENDING FOLLOWERS list.
    // This action implicitly checks if the request exists. If it doesn't exist, Prisma performs a no-op (no error).
    try {
        await prisma.user.update({
            where: { id: targetUserId },
            data: {
                pendingFollowers: {
                    // Disconnect the current user (follower) from the pendingFollowers relation of the target.
                    disconnect: { id: currentUserId },
                },
            },
        });
    } catch (error) {
        // If the update fails for a reason other than not found (which is checked above), 
        // log or handle the error. For a disconnect operation, a general failure here 
        // is rare if the IDs are valid.
        console.error("Prisma update failed during follow request cancellation:", error);
        throw new Error("Failed to cancel follow request due to a database error.");
    }
    
    // Note: No side effects (like sending a notification) are typically needed for a cancellation.

    return { success: true };
};



// ----------------------------------- Main Service Logic ------------------------------------------------------------------



/**
 * API: Accept Follow Request
 * @description Accepts a pending follow request from a requester.
 * @param currentUserId The ID of the user accepting the request (the target).
 * @param requesterId The ID of the user who sent the request (the follower).
 * @returns { success: boolean }
 */
export const acceptFollowRequest = async (currentUserId: string, requesterId: string): Promise<{ success: boolean }> => {
    
    // 1. Pre-check: Ensure the requester exists and is in the current user's pending list.
    const requester = await prisma.user.findUnique({
        where: { id: requesterId },
        select: { id: true, username: true }
    });

    if (!requester) {
        throw new NotFoundError(`Requester with ID ${requesterId} not found.`, 404);
    }
    
    // We must check if the request is actually pending. We query the target's (current user's)
    // pendingFollowers relationship for the requester's ID.
    const pendingRequest = await prisma.user.findUnique({
        where: { id: currentUserId },
        select: { 
            pendingFollowers: { 
                where: { id: requesterId }, 
                select: { id: true } 
            } 
        }
    });

    if (!pendingRequest || pendingRequest.pendingFollowers.length === 0) {
        // This means the request was already accepted, denied, or never sent.
        throw new NotFoundError("No pending follow request found from this user.", 404);
    }

    // 2. Core Logic: Atomic Transaction
    const [updatedTargetUser, notification] = await prisma.$transaction(async (tx) => {
        // 2.1 Remove requesterId from pendingFollowers (Disconnect pending relation)
        await tx.user.update({
            where: { id: currentUserId },
            data: {
                pendingFollowers: {
                    disconnect: { id: requesterId },
                },
            },
        });

        // 2.2 Add requesterId to target's followers and target to requester's following (Connect active relation)
        const updatedTarget = await tx.user.update({
            where: { id: currentUserId },
            data: {
                // Connect the requester (follower) to the target's 'followers' relation.
                followers: {
                    connect: { id: requesterId },
                },
            },
            select: { id: true } // Select minimal data
        });

        // 2.3 Side Effect: Create 'follow' Notification
        const notificationRecord = await tx.notification.create({
            data: {
                userId: requesterId,      // User receiving the notification (the new follower)
                actorId: currentUserId,    // User who accepted the request
                type: 'follow' as NotificationType, 
                content: `${requester.username} is now following you!`, 
                link: `/profile/${currentUserId}`, // Link back to the acceptor's profile
            }
        });

        return [updatedTarget, notificationRecord];
    });


    // 3. Realtime Side Effect
    // Emit the notification object to the requester's channel
    emitWebSocketEvent(`user:${requesterId}`, { type: 'newNotification', data: notification });

    return { success: true };
};



// ----------------------------------- Main Service Logic ------------------------------------------------------------------



/**
 * API: Decline Follow Request
 * @description Declines a pending follow request from a requester.
 * @param currentUserId The ID of the user declining the request (the target).
 * @param requesterId The ID of the user who sent the request (the follower).
 * @returns { success: boolean }
 */
export const declineFollowRequest = async (currentUserId: string, requesterId: string): Promise<{ success: boolean }> => {
    
    // 1. Pre-check: Ensure the requester exists.
    const requester = await prisma.user.findUnique({
        where: { id: requesterId },
        select: { id: true }
    });

    if (!requester) {
        // We use 404 here, but 400 Bad Request could also be justified if the request ID is just invalid.
        throw new NotFoundError(`Requester with ID ${requesterId} not found.`, 404);
    }

    // 2. Core Logic: Atomically disconnect the requester from the current user's PENDING FOLLOWERS list.
    // NOTE: If the request doesn't exist (i.e., it was already accepted or deleted), 
    // Prisma's 'disconnect' performs a safe no-op. No explicit check for existence is needed.
    try {
        await prisma.user.update({
            where: { id: currentUserId },
            data: {
                pendingFollowers: {
                    disconnect: { id: requesterId },
                },
            },
        });
    } catch (error) {
        // Log database-level errors
        console.error("Prisma update failed during follow request decline:", error);
        throw new Error("Failed to decline follow request due to a database error.");
    }
    
    // 3. Side Effects: None, as per business logic.

    return { success: true };
};


// ----------------------------------- Main Service Logic ------------------------------------------------------------------


/**
 * API: Unfollow User
 * @description Removes a follow relationship between the current user and the target user.
 * @param currentUserId The ID of the user performing the unfollow.
 * @param targetUserId The ID of the user being unfollowed.
 * @returns { success: boolean }
 */
export const unfollowUser = async (currentUserId: string, targetUserId: string): Promise<{ success: boolean }> => {
    
    // 1. Pre-check: Ensure the target user exists
    const targetUser = await prisma.user.findUnique({
        where: { id: targetUserId },
        select: { id: true }
    });

    if (!targetUser) {
        throw new NotFoundError(`User with ID ${targetUserId} not found.`, 404);
    }
    
    // 2. Core Logic: Atomic Disconnection
    // We update the current user (disconnecting the target from their 'following' list)
    // AND update the target user (disconnecting the current user from their 'followers' list).
    await prisma.$transaction([
        // Update the current user (the unfollower)
        prisma.user.update({
            where: { id: currentUserId },
            data: {
                following: {
                    disconnect: { id: targetUserId }, // Remove target from current user's 'following' list
                },
            },
        }),
        
        // Update the target user (the unfollowed)
        prisma.user.update({
            where: { id: targetUserId },
            data: {
                followers: {
                    disconnect: { id: currentUserId }, // Remove current user from target's 'followers' list
                },
            },
        }),
    ]);
    
    // Note: If the relationship didn't exist, Prisma performs a safe no-op.

    return { success: true };
};

// ----------------------------------- Main Service Logic ------------------------------------------------------------------


/**
 * API: Block User
 * @description Blocks a target user, atomically removing all existing social relationships.
 * @param currentUserId The ID of the user performing the block.
 * @param targetUserId The ID of the user being blocked.
 * @returns { success: boolean }
 */
export const blockUser = async (currentUserId: string, targetUserId: string): Promise<{ success: boolean }> => {
    
    // Pre-conditions: Current user cannot block themselves.
    if (currentUserId === targetUserId) {
        throw new BadRequestError("You cannot block yourself.", 400);
    }
    
    // Pre-check: Ensure the target user exists
    const targetUser = await prisma.user.findUnique({
        where: { id: targetUserId },
        select: { id: true }
    });

    if (!targetUser) {
        throw new NotFoundError(`User with ID ${targetUserId} not found.`, 404);
    }

    // @transactional: Core Logic is atomic.
    await prisma.$transaction([
        // 1. Core Logic: Add userId to the current user's blockedUsers (Connect block relationship).
        // (Prisma relational update handles the "prevent duplicates" requirement implicitly).
        prisma.user.update({
            where: { id: currentUserId },
            data: {
                blockedUsers: {
                    connect: { id: targetUserId },
                },
            },
        }),

        // 2. Remove userId from the current user's followingIds (Disconnect current user's 'following' relation)
        prisma.user.update({
            where: { id: currentUserId },
            data: {
                following: {
                    disconnect: { id: targetUserId },
                },
            },
        }),
        
        // 3. Remove the current user's ID from the userId's followingIds (Disconnect target user's 'followers' relation)
        prisma.user.update({
            where: { id: targetUserId },
            data: {
                followers: {
                    disconnect: { id: currentUserId },
                },
            },
        }),

        // 4. Remove any pending follow requests between the two users.
        // Disconnect target from current user's 'pendingFollowing'
        prisma.user.update({
            where: { id: currentUserId },
            data: {
                pendingFollowing: {
                    disconnect: { id: targetUserId },
                },
            },
        }),
        // Disconnect current user from target user's 'pendingFollowers'
        prisma.user.update({
            where: { id: targetUserId },
            data: {
                pendingFollowers: {
                    disconnect: { id: currentUserId },
                },
            },
        }),
    ]);
    
    return { success: true };
};

// ----------------------------------- Main Service Logic ------------------------------------------------------------------

/**
 * API: Unblock User
 * @description Removes the block relationship between the current user and the target user.
 * @param currentUserId The ID of the user performing the unblock.
 * @param targetUserId The ID of the user being unblocked.
 * @returns { success: boolean }
 */
export const unblockUser = async (currentUserId: string, targetUserId: string): Promise<{ success: boolean }> => {
    
    if (currentUserId === targetUserId) {
        throw new BadRequestError("You cannot unblock yourself.", 400);
    }
    
    const targetUser = await prisma.user.findUnique({
        where: { id: targetUserId },
        select: { id: true }
    });

    if (!targetUser) {
        throw new NotFoundError(`User with ID ${targetUserId} not found.`, 404);
    }

    // @coreLogic: Remove userId from the current user's blockedUserIds (Disconnect block relationship).
    await prisma.user.update({
        where: { id: currentUserId },
        data: {
            blockedUsers: {
                disconnect: { id: targetUserId },
            },
        },
    });

    return { success: true };
};



// ----------------------------------- Main Service Logic ------------------------------------------------------------------


/**
 * API: Add Review
 * @description Submits a review for another user, with optional transaction verification.
 * @param currentUserId The ID of the authenticated user submitting the review.
 * @param targetUserId The ID of the user being reviewed.
 * @param reviewData The review content (rating, comment, transactionId).
 * @returns { Review } The newly created Review object.
 */
export const addReview = async (
    currentUserId: string, 
    targetUserId: string, 
    reviewData: AddReviewPayload
): Promise<Review> => {

    const { rating, comment, transactionId } = reviewData;

    // @businessLogic: Pre-conditions: A user cannot review themselves.
    if (currentUserId === targetUserId) {
        throw new BadRequestError("You cannot review yourself.", 400);
    }
    
    // Check if the target user exists
    const targetUser = await prisma.user.findUnique({ where: { id: targetUserId } });
    if (!targetUser) {
        throw new NotFoundError("User being reviewed not found.", 404);
    }

    let isVerifiedPurchase = false;

    if (transactionId) {
        // @businessLogic: Check for duplicate review by transaction
        const existingReview = await prisma.review.findFirst({
            where: {
                reviewerId: currentUserId,
                userId: targetUserId,
                transactionId: transactionId,
            }
        });

        // @errorHandling: 409 Conflict
        if (existingReview) {
            throw new ConflictError("A review for this transaction by you already exists.", 409);
        }

        // @coreLogic: Validate transaction details
        const transaction = await prisma.transaction.findUnique({
            where: { id: transactionId }
        });

        if (!transaction) {
             throw new NotFoundError(`Transaction with ID ${transactionId} not found.`, 404);
        }

        // Validate the roles in the transaction
        const isReviewerBuyer = transaction.buyerId === currentUserId;
        const isReviewedSeller = transaction.sellerId === targetUserId;

        // @errorHandling: 403 Forbidden
        if (!isReviewerBuyer || !isReviewedSeller) {
            throw new ForbiddenError(
                "You can only review the seller if you were the buyer in this transaction.", 
                403
            );
        }

        // If all checks pass, mark as verified
        isVerifiedPurchase = true;
    }


    // @coreLogic: Create a new Review record.
    const newReview = await prisma.review.create({
        data: {
            rating: rating,
            comment: comment,
            reviewerId: currentUserId,
            UserId: targetUserId,
            transactionId: transactionId,
            isVerifiedPurchase: isVerifiedPurchase,
        }
    });

    return newReview;
};
