// src/api/v1/controllers/auth.controller.ts

import { Request, Response, NextFunction  } from 'express';
import { loginUser, logFailedLogin, signUp, verifyEmailByOtp, resendVerificationOtp, requestPasswordReset, resetPassword, signOut } from '../../../../src/services/auth.service';
import { UserRole } from '@prisma/client';
import { AuthenticationError } from '../../../errors/AuthenticationError';
import { AuthenticatedRequest } from '../../../middlewares/auth.middleware';

/**
 * Handles the POST /api/v1/auth/login endpoint.
 * @route POST /api/v1/auth/login
 */
export const login = async (req: Request, res: Response) => {
  const { identifier, password } = req.body;
  const ip = req.ip || 'N/A'; // Get IP address
  const userAgent = req.headers['user-agent']; // Get User-Agent

  try {
    const { user, token } = await loginUser({ identifier, password });

    // --- 5. Set Secure HttpOnly Cookie ---
    const maxAge = 86400 * 1000; // 24 hours in milliseconds

    res.cookie('token', token, {
      maxAge: maxAge, // Max-Age=86400
      httpOnly: true, // HttpOnly
      // Check the environment: Secure MUST be true in production (HTTPS), false in development (HTTP)
      secure: process.env.NODE_ENV === 'production', // <-- CRITICAL FIX HERE
      sameSite: 'strict', // SameSite=Strict
      path: '/', // Path=/
    });

    res.status(200).json({
      status: 'success',
      data: {
        user: user,
        token: token,
      },
      message: 'Login successful.',
    });

  } catch (error: any) {
    // Determine status code based on service layer error
    const statusCode = error.statusCode || 500;
    
    // Auditing: Log Failed Login Attempt
    await logFailedLogin(identifier, ip, userAgent);

    // Differentiate between 401 (Auth failure) and 403/503 (Account/Service restriction)
    if (statusCode === 401) {
        res.status(401).json({
            status: 'error',
            message: 'Invalid identifier or password.',
        });
    } else if (statusCode === 403 || statusCode === 503) {
        res.status(statusCode).json({
            status: 'error',
            message: error.message,
        });
    } else {
        // Internal Server Error
        console.error('Login internal error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An unexpected server error occurred during login.',
        });
    }
  }
};




/**
 * Handles the sign-up request.
 */
export const signup = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
             throw new AuthenticationError('Missing required credentials.', 400);
        }

        // Call the service layer with the required data
        const { user, token } = await signUp({
            username,
            email,
            password,
        });

        // Success: Return 201 Created
        return res.status(201).json({
            status: 'success',
            message: 'User created successfully. Verification email sent.',
            data: { user, token },
        });

    } catch (error) {
        // Pass error (including AuthenticationError) to the central error handler
        next(error);
    }
};



/**
 * Handles the authenticated email verification request.
 * Requires authMiddleware to run first.
 */
export const verifyEmail = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
        const { otp } = req.body;
        const userId = req.userId; // Retrieved from the JWT by authMiddleware

        if (!userId) {
            // This should ideally be caught by authMiddleware, but is a safe check
            throw new AuthenticationError('Authentication required.', 401);
        }
        if (!otp) {
             throw new AuthenticationError('Verification code is required.', 400);
        }

        const result = await verifyEmailByOtp({ userId, otp });

        return res.status(200).json({
            status: 'success',
            message: 'Email successfully verified.',
            ...result, // { success: true }
        });
    }

      catch (error) {
        next(error);
    }
};
      /**
 * Handles the authenticated request to resend the verification OTP.
 * Requires authMiddleware to run first.
 */
export const resendOtp = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
        const userId = req.userId; // Retrieved from the JWT by authMiddleware

        if (!userId) {
            // Should be caught by middleware, but a safeguard.
            throw new AuthenticationError('Authentication token missing or invalid.', 401);
        }

        const result = await resendVerificationOtp(userId);

        return res.status(200).json({
            status: 'success',
            message: 'A new verification code has been sent to your email.',
            ...result, // { success: true }
        });

    } catch (error) {
        next(error);
    }
};




/**
 * Handles the request to initiate the password reset process.
 */
export const requestReset = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { email } = req.body;

        if (!email) {
             throw new AuthenticationError('Email address is required to request a password reset.', 400);
        }

        // Call the service, which handles user lookup and security checks internally.
        const result = await requestPasswordReset(email);

        // ALWAYS return 200 OK to prevent enumeration attacks.
        return res.status(200).json({
            status: 'success',
            message: 'If an account with that email exists, a password reset code has been sent.',
            ...result, // { success: true }
        });

    } catch (error) {
        // Only internal errors (like DB failure) should reach here, not business logic errors.
        next(error);
    }
};



/**
 * Handles the request to set a new password using an OTP.
 */
export const resetPasswordController = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { email, otp, newPassword } = req.body;

        if (!email || !otp || !newPassword) {
             throw new AuthenticationError('Email, OTP, and a new password are required.', 400);
        }

        const result = await resetPassword({ email, otp, newPassword });

        // Success: 200 OK
        return res.status(200).json({
            status: 'success',
            message: 'Password has been reset successfully. You may now log in.',
            ...result, // { success: true }
        });

    } catch (error) {
        // Catches AuthenticationError for invalid OTP/email/weak password
        next(error);
    }
};



/**
 * API: Sign Out
 * @description Logs out the user by clearing the session cookie and blocklisting the JWT.
 */
export const signOutController = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
        const userId = req.userId;
        const token = req.token;

        if (!userId || !token) {
            throw new AuthenticationError('Authentication token missing or invalid.', 401);
        }

        // 1. Server-side Blocklisting
        await signOut(token, userId);

        // 2. Client-side Invalidation: Clear the HttpOnly cookie
        res.clearCookie('jwt', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict', // Use the same options used when setting the cookie
        });

        // 3. Success Response
        return res.status(200).json({
            status: 'success',
            message: 'Successfully signed out.',
            success: true
        });

    } catch (error) {
        next(error);
    }
};
