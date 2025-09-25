// src/api/v1/controllers/auth.controller.ts

import { Request, Response, NextFunction  } from 'express';
import { loginUser, logFailedLogin, signUp } from '../../../../src/services/auth.service';
import { UserRole } from '@prisma/client';
import { AuthenticationError } from '../../../errors/AuthenticationError';

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
