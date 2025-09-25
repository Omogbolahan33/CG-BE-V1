// src/api/v1/routes/auth.route.ts

import { Router } from 'express';
import { login, signup, verifyEmail, resendOtp } from '../controllers/auth.controller';
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


export default router;
