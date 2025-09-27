import prisma from '../utils/prisma';
import { Transaction, Post, User } from '../types'; 
import { ForbiddenError } from '../errors/ForbiddenError';
import { BadRequestError } from '../errors/BadRequestError'; 
import { NotFoundError } from '../errors/NotFoundError';
import { getBackofficeSettings } from '../utils/settings.util';
import { queueJob } from '../utils/job-queue.util';
import { UserRole, TransactionStatus, Prisma } from '@prisma/client';
import { processPayment, PaymentStatus } from '../utils/payment-processor.util'; 

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





/**
 * API: Create Transaction
 * @description Initiates a purchase for an item, processes payment, and sets status to 'In Escrow', 'Pending', or 'Cancelled'.
 */
export const createTransaction = async (
    postId: string, 
    deliveryFee: number,
    currentAuthUserId: string,
    currentUserRole: UserRole
): Promise<Transaction> => {
    
    // 1. Fetch Post, Buyer, and Settings atomically
    const [post, buyer, settings, admins] = await Promise.all([
        // ... (Post, Buyer, Settings fetching logic remains the same) ...
        prisma.post.findUnique({
            where: { id: postId },
            select: { 
                id: true, 
                authorId: true, 
                price: true, 
                isSoldOut: true, 
                title: true,
            }
        }),
        prisma.user.findUnique({
            where: { id: currentAuthUserId },
            select: { 
                id: true, 
                address: true, 
                city: true, 
                zipCode: true,
                email: true
            }
        }),
        getBackofficeSettings(),
        prisma.user.findMany({
            where: { role: { in: [UserRole.Admin, UserRole.SuperAdmin] } },
            select: { id: true }
        })
    ]);

    if (!post || !buyer) {
        throw new NotFoundError('Post or user not found.');
    }
    
    // --- 2. Pre-conditions Check (Authorization, Sold Out, Self-Purchase, Address) ---
    // ... (All pre-conditions logic remains the same) ...
    const enablePayments = settings.enablePayments;
    const canPay = currentUserRole !== UserRole.Member || enablePayments;
    
    if (!canPay) {
        throw new ForbiddenError('Payments are currently disabled.');
    }
    if (post.isSoldOut) {
        throw new BadRequestError('This item is already sold out.');
    }
    if (post.authorId === currentAuthUserId) {
        throw new BadRequestError('You cannot purchase your own item.');
    }
    if (!buyer.address || !buyer.city || !buyer.zipCode) {
        throw new BadRequestError('Please complete your shipping address before proceeding with a purchase.');
    }

    // --- 3. Payment Processing (External Call) ---
    const itemPrice = post.price || 0;
    const totalAmount = itemPrice + deliveryFee;

    // ✅ FIX: Call the external utility
    const paymentResult = await processPayment(totalAmount); 
    
    let transactionStatus: TransactionStatus;

    // --- 4. Transaction Creation (Atomic) ---
    const newTransaction = await prisma.$transaction(async (tx) => {
        
        // Map external payment status to internal TransactionStatus enum
        switch (paymentResult.status) {
            case 'SUCCESS':
                transactionStatus = TransactionStatus.InEscrow;
                // On success, also mark the post as sold out within the transaction
                await tx.post.update({
                    where: { id: postId },
                    data: { isSoldOut: true }
                });
                break;
            case 'PENDING':
                transactionStatus = TransactionStatus.Pending;
                break;
            case 'FAILURE':
            default:
                transactionStatus = TransactionStatus.Cancelled;
                break;
        }

        const createdTransaction = await tx.transaction.create({
            data: {
                post: { connect: { id: postId } },
                buyer: { connect: { id: currentAuthUserId } },
                seller: { connect: { id: post.authorId } },
                itemPrice: itemPrice,
                deliveryFee: deliveryFee,
                totalAmount: totalAmount,
                status: transactionStatus, // Use determined status
                paymentReference: paymentResult.reference,
                failureReason: paymentResult.failureReason,
                shippingAddress: `${buyer.address}, ${buyer.city}, ${buyer.zipCode}`,
            } as Prisma.TransactionCreateInput
        }) as unknown as Transaction;
        
        return createdTransaction;
    });

    // --- 5. Side Effects (Notifications & Realtime) ---
    // ... (Notification logic remains largely the same, but adapts to PENDING status) ...
    
    const transactionDetails = { 
        transactionId: newTransaction.id, 
        postId: postId,
        postTitle: post.title,
        buyerId: currentAuthUserId, 
        sellerId: post.authorId 
    };

    if (paymentResult.status === 'SUCCESS') {
        // Notifications for successful escrow
        queueJob('SEND_NOTIFICATION', { type: 'TRANSACTION_ESCROW_SECURED', recipientId: post.authorId, details: { ...transactionDetails, message: "Payment is secured, you can now ship the item." } });
        queueJob('SEND_NOTIFICATION', { type: 'TRANSACTION_SUCCESS', recipientId: currentAuthUserId, details: { ...transactionDetails, message: "Your payment was successful and is now in escrow." } });
        admins.forEach(admin => {
            queueJob('SEND_NOTIFICATION', { type: 'NEW_ESCROW_TRANSACTION', recipientId: admin.id, details: { ...transactionDetails, message: `New escrow funded transaction for post ${post.title}.` } });
        });

    } else if (paymentResult.status === 'PENDING') {
        // New: Notifications for pending status
        queueJob('SEND_NOTIFICATION', { type: 'TRANSACTION_PENDING', recipientId: currentAuthUserId, details: { ...transactionDetails, message: "Your payment is pending confirmation." } });
        queueJob('SEND_NOTIFICATION', { type: 'TRANSACTION_PENDING_SELLER', recipientId: post.authorId, details: { ...transactionDetails, message: "A transaction for your post is awaiting payment confirmation." } });
        
    } else if (paymentResult.status === 'FAILURE') {
        // Notifications for failed payment
        queueJob('SEND_NOTIFICATION', { type: 'TRANSACTION_FAILED', recipientId: currentAuthUserId, details: { ...transactionDetails, failureReason: paymentResult.failureReason, message: "Your payment failed." } });
    }

    // Realtime update logic
    // queueJob('EMIT_REALTIME_UPDATE', { /* ... */ });

    return newTransaction;
};
