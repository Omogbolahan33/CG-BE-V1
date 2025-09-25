// src/api/v1/routes/auth.route.ts

import { Router } from 'express';
import { login, signup, verifyEmail } from '../controllers/auth.controller';
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




export default router;
