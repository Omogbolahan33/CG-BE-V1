import { Request, Response, NextFunction } from 'express';
import { getTransactions, createTransaction, updateTransaction } from '../../../services/transaction.service';
import { UserRole } from '@prisma/client';
import { BadRequestError } from '../../../errors/BadRequestError';


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



/**
 * Controller: Create Transaction
 */
export const createTransactionController = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const { postId, deliveryFee } = req.body;
        const currentAuthUserId = req.userId;
        const currentUserRole = req.userRole;

        if (!currentAuthUserId || !currentUserRole) {
            return res.status(403).json({ message: 'Authentication required.' });
        }
        
        if (!postId || typeof deliveryFee !== 'number') {
             throw new BadRequestError('Invalid input. postId and deliveryFee are required.');
        }

        const newTransaction = await createTransaction(
            postId, 
            deliveryFee, 
            currentAuthUserId,
            currentUserRole
        );

        // Success response
        return res.status(201).json(newTransaction);

    } catch (error: any) {
        next(error);
    }
};



/**
 * Controller: Update Transaction Status
 */
export const updateTransactionController = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const transactionId = req.params.transactionId;
        // status and trackingNumber come from the JSON body
        const { status, trackingNumber } = req.body; 
        // proofOfShipment comes from the file upload middleware (req.file or similar)
        const proofOfShipment = req.file; 
        
        const currentAuthUserId = req.userId;
        const currentUserRole = req.userRole;

        if (!currentAuthUserId || !currentUserRole) {
            return res.status(403).json({ message: 'Authentication required.' });
        }
        
        // Pass only the fields that were actually provided in the request
        const updates = { 
            status: status, 
            trackingNumber: trackingNumber, 
            proofOfShipment: proofOfShipment 
        };

        const updatedTransaction = await updateTransaction(
            transactionId, 
            updates, 
            currentAuthUserId,
            currentUserRole
        );

        return res.status(200).json(updatedTransaction);

    } catch (error: any) {
        next(error);
    }
};
