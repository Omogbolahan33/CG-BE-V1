import { Request, Response, NextFunction } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import prisma from '../utils/prisma';
import { AuthenticationError } from '../errors/AuthenticationError';
// 🔥 NEW IMPORT: Import the concrete AuthUser type
import { AuthUser } from '../types'; 

// Extend the Express Request interface to include the full AuthUser object
export interface AuthenticatedRequest extends Request {
    // We will attach the full user object here
    user?: AuthUser;
    // Keep token for debugging if needed
    token?: string; 
    // Remove individual userId and role properties as they will be on req.user
    userId?: string; 
    role?: string; 
}

/**
 * Middleware to verify the JWT and attach complete user data to the request (req.user).
 */
export const authMiddleware = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
        const secret = process.env.JWT_SECRET;
        if (!secret) {
            // Log this as a critical configuration error
            console.error('CRITICAL: JWT_SECRET is not configured.');
            throw new Error('Server configuration error.');
        }
            
        let token: string | undefined; 
        
        // 1. Get token from Authorization header or cookie
        const authHeader = req.headers.authorization;
        token = (authHeader && authHeader.startsWith('Bearer ')) ? authHeader.split(' ')[1] : req.cookies?.jwt;
        
        // 2. Handle missing token
        if (!token) {
            throw new AuthenticationError('Authentication token missing.', 401);
        }

        req.token = token; // Attach for logging/debugging

        // 3. Verify and decode the JWT
        const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] }) as JwtPayload;
        const userId = decoded.userId as string;

        // 4. 🔥 OPTIMIZED DB QUERY: Fetch all required business logic flags in one call
        const user = await prisma.user.findUnique({
            where: { id: userId },
            select: { 
                id: true, 
                role: true, 
                isActive: true,
                // CRITICAL: isBanned status for post creation pre-condition
                banExpiresAt: true, 
                // CRITICAL: Check for existence of bank account for advert pre-condition
                bankAccount: { select: { id: true } } 
            }
        });

        const isBanned = user?.banExpiresAt ? user.banExpiresAt > new Date() : false;
        const hasBankAccount = !!user?.bankAccount;

        if (!user || !user.isActive) {
            throw new AuthenticationError('User session invalid or account inactive.', 401);
        }

        // 5. BUSINESS LOGIC: UPDATE lastSeen TIMESTAMP (Non-blocking)
        prisma.user.update({
            where: { id: userId },
            data: { lastSeen: new Date() },
        }).catch(err => {
            console.error(`Failed to update lastSeen for user ${userId}:`, err);
        });
        
        // 6. 🔥 ATTACH FULL AUTHUSER OBJECT to the request object
        const authUser: AuthUser = {
            id: user.id,
            role: user.role,
            isBanned: isBanned, // The computed ban status
            hasBankAccount: hasBankAccount, // The computed bank account status
        };
        
        req.user = authUser;
        // Keep req.userId/req.role for legacy or external consumers, but they are DEPRECATED
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
