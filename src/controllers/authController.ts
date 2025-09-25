import { Request, Response } from 'express';
import { loginUser } from '../services/authService';
import { sanitizeUser } from '../utils/sanitizeUser';
import { asyncHandler } from '../middleware/asyncHandler';

export const login = asyncHandler(async (req: Request, res: Response) => {
  const { identifier, password } = req.body;

  const { user, token } = await loginUser({ identifier, password });

  // Secure HttpOnly cookie
  res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 1000 * 60 * 60 * 24, // 1 day
  });

  res.json({
    user: sanitizeUser(user),
    token, // also return in body for mobile clients
  });
});
