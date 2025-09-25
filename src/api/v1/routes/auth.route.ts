// src/api/v1/routes/auth.route.ts

import { Router } from 'express';
import { login, signup, verifyEmail, resendOtp, requestReset, resetPasswordController  } from '../controllers/auth.controller';
import { loginRateLimiter } from '../../../middlewares/rateLimiter';
import { authMiddleware } from '../../../middlewares/auth.middleware';

const router = Router();

// POST /api/v1/auth/login - Login User (Rate-limited)
// Apply the rate limiter middleware only to the login route for security
router.post('/login', loginRateLimiter, login);

// Route for new user registration
// Matches the documentation: /auth/signup
router.post('/signup', signup); 

// Route for authenticated email verification
router.post('/verify-email', authMiddleware, verifyEmail); 

// Route for resending verification OTP
router.post('/resend-verification-otp', authMiddleware, resendOtp);

// Route for requesting password reset
router.post('/request-password-reset', requestReset);

// Route for resetting password with OTP
router.post('/reset-password', resetPasswordController);

export default router;
