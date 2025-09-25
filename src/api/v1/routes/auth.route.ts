// src/api/v1/routes/auth.route.ts

import { Router } from 'express';
import * as authController from '../controllers/auth.controller';
import { loginRateLimiter } from '../../../middlewares/rateLimiter'; // Import the middleware

const router = Router();

// POST /api/v1/auth/login - Login User (Rate-limited)
// Apply the rate limiter middleware only to the login route for security
router.post('/login', loginRateLimiter, authController.login);

export default router;
