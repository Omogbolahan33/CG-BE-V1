import { Request, Response, NextFunction } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import prisma from '../utils/prisma';
import { AuthenticationError } from '../errors/AuthenticationError';

// Extend the Express Request interface to include the user object
export interface AuthenticatedRequest extends Request {
    userId?: string;
    role?: string;
}

/**
 * Middleware to verify the JWT and attach user data to the request.
 */
export const authMiddleware = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
        const secret = process.env.JWT_SECRET;
        if (!secret) {
            throw new Error('JWT_SECRET is not configured.');
        }

        // 1. Get token from Authorization header (Bearer <token>)
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            // Check for cookie as fallback (if set during login)
            const token = req.cookies?.jwt;
            if (!token) {
                 throw new AuthenticationError('Authentication token missing.', 401);
            }
            req.token = token;
        } else {
            req.token = authHeader.split(' ')[1];
        }

        // 2. Verify and decode the JWT
        const decoded = jwt.verify(req.token, secret, { algorithms: ['HS256'] }) as JwtPayload;
        const userId = decoded.userId as string;

        // 3. Check if user exists and is active (Optional, but good security)
        const user = await prisma.user.findUnique({
            where: { id: userId },
            select: { id: true, role: true, isActive: true }
        });

        if (!user || !user.isActive) {
            throw new AuthenticationError('User session invalid or account inactive.', 401);
        }

        // 4. Attach user data to the request object
        req.userId = user.id;
        req.role = user.role;
        
        next();

    } catch (error) {
        // Handle JWT verification errors (e.g., expired, invalid signature)
        if (error instanceof jwt.JsonWebTokenError) {
             return next(new AuthenticationError('Invalid token or expired session.', 401));
        }
        next(error);
    }
};
