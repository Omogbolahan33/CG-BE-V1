// src/middlewares/rateLimiter.ts

import rateLimit from 'express-rate-limit';

/**
 * Rate Limiter for the Authentication endpoints (specifically login).
 * @limit 5 requests
 * @windowMs 10 minutes (10 * 60 * 1000 ms)
 */
export const loginRateLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 5, // Limit each IP/identifier to 5 requests per windowMs
  keyGenerator: (req) => {
    // Use the identifier from the request body as part of the key for user-specific limiting
    const identifier = req.body.identifier || req.ip;
    return `login_attempt_${identifier}`;
  },
  handler: (req, res) => {
    res.status(429).json({
      status: 'error',
      message: 'Too many failed login attempts. Please try again after 10 minutes.'
    });
  },
  standardHeaders: true, // Return rate limit info in the headers
  legacyHeaders: false, // Disable the X-Rate-Limit-* headers
});
