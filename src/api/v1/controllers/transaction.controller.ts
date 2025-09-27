import { Request, Response, NextFunction } from 'express';
import { getTransactions } from '../services/transaction.service';
import { UserRole } from '@prisma/client';

// Custom interface for authenticated request
interface AuthRequest extends Request {
    userId?: string;
    userRole?: UserRole; 
}

/**
 * Controller: Get User Transactions
 */
export const getTransactionsController = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const currentAuthUserId = req.userId;

        if (!currentAuthUserId) {
            // Should be caught by authMiddleware, but defensive check remains
            return res.status(403).json({ message: 'Authentication required.' });
        }

        const transactions = await getTransactions(currentAuthUserId);

        return res.status(200).json(transactions);

    } catch (error: any) {
        next(error);
    }
};

