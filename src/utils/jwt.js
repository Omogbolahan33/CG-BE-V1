import jwt from 'jsonwebtoken';
import crypto from 'crypto';

export const generateToken = (payload, expiresIn = '7d') => {
  const jti = crypto.randomUUID();
  return jwt.sign({ ...payload, jti }, process.env.JWT_SECRET, { expiresIn });
};
