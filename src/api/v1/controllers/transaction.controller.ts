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
 * Handles updates to transaction status, tracking number, and shipping proof.
 */
export const updateTransactionController = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const { transactionId } = req.params;
        const { status, trackingNumber } = req.body;
        
        // File is attached by Multer middleware
        const proofOfShipment = req.file;
        
        const { userId: currentAuthUserId, userRole: currentUserRole } = req;

        // --- Authentication & Input Checks ---
        if (!currentAuthUserId || !currentUserRole) {
            return res.status(403).json({ message: 'Authentication required.' });
        }
        if (!transactionId) {
             // Use your custom error if available, or throw a standard Error
             throw new Error('Transaction ID is required.'); 
        }

        // --- Construct Update Payload ---
        // Build the updates object, including only fields that are actually present.
        const updates = Object.assign(
            {},
            status && { status },
            trackingNumber && { trackingNumber },
            proofOfShipment && { proofOfShipment } // Pass the file object/buffer
        );
        
        // If no valid update fields were provided, the service layer will likely catch it,
        // but a quick check here is also fine.
        if (Object.keys(updates).length === 0) {
            throw new BadRequestError('No valid update fields provided.');
        }


        // --- Service Call ---
        const updatedTransaction = await updateTransaction(
            transactionId,
            updates,
            currentAuthUserId,
            currentUserRole
        );

        // --- Response ---
        return res.status(200).json(updatedTransaction);

    } catch (error) {
        // Pass the error to the global error handler middleware
        next(error);
    }
};
