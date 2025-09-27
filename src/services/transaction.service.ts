import prisma from '../utils/prisma';
import { Transaction } from '../types'; 

/**
 * API: Get User Transactions
 * @description Fetches all transactions for the current user (where they are buyer or seller).
 */
export const getTransactions = async (currentAuthUserId: string): Promise<Transaction[]> => {
    
    // Fetch transactions where the user is either the buyer or the seller.
    const transactions = await prisma.transaction.findMany({
        where: {
            OR: [
                { buyerId: currentAuthUserId },
                { sellerId: currentAuthUserId },
            ],
        },
        orderBy: {
            date: 'desc', // Typically, transactions are ordered by newest first
        },
        // Include relevant relations if needed, e.g., include: { post: true, buyer: true, seller: true }
    }) as unknown as Transaction[]; // Cast to your simple Transaction type

    return transactions;
};
