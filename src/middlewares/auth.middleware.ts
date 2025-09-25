import { Request, Response, NextFunction } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import prisma from '../utils/prisma';
import { AuthenticationError } from '../errors/AuthenticationError';

// Extend the Express Request interface to include the user object
export interface AuthenticatedRequest extends Request {
    userId?: string;
    role?: string;
    token?: string;
}

/**
 * Middleware to verify the JWT and attach user data to the request...
 */
export const authMiddleware = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
        const secret = process.env.JWT_SECRET;
        if (!secret) {
            throw new Error('JWT_SECRET is not configured.');
        }
            let token: string | undefined; // Use a local variable to hold the token
        
        // 1. Get token from Authorization header (Bearer <token>)
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            // Check for cookie as fallback (if set during login)
            token = req.cookies?.jwt;
        } else {
            token = authHeader.split(' ')[1];
        }
        
        // 2. Handle missing token
        if (!token) {
             throw new AuthenticationError('Authentication token missing.', 401);
        }

        // We can still assign it to the request object for logging/debugging if needed:
        req.token = token; 

        // 3. Verify and decode the JWT
        const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] }) as JwtPayload;
        const userId = decoded.userId as string;

        // 4. Check if user exists and is active (Optional, but good security)
        const user = await prisma.user.findUnique({
            where: { id: userId },
            select: { id: true, role: true, isActive: true }
        });

        if (!user || !user.isActive) {
            throw new AuthenticationError('User session invalid or account inactive.', 401);
        }

        // 5. ***BUSINESS LOGIC: UPDATE lastSeen TIMESTAMP***
        // We use a non-blocking update here so the middleware doesn't slow down the main thread.
        // The main goal is high availability and low latency on every request.
        prisma.user.update({
            where: { id: userId },
            data: { lastSeen: new Date() },
        }).catch(err => {
            console.error(`Failed to update lastSeen for user ${userId}:`, err);
            // We still proceed with the request even if the lastSeen update fails.
        });
        
        // 6. Attach user data to the request object
        req.userId = user.id;
        req.role = user.role;
        
        next();

    } catch (error) {
        // ... rest of the error handling ...
        if (error instanceof jwt.JsonWebTokenError) {
             return next(new AuthenticationError('Invalid token or expired session.', 401));
        }
        next(error);
    }
};
