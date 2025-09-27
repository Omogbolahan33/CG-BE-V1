import prisma from '../utils/prisma';
import { Transaction, Post, User } from '../types'; 
import { ForbiddenError } from '../errors/ForbiddenError';
import { BadRequestError } from '../errors/BadRequestError'; 
import { NotFoundError } from '../errors/NotFoundError';
import { getBackofficeSettings } from '../utils/settings.util';
import { queueJob } from '../utils/job-queue.util';
import { UserRole, TransactionStatus, Prisma } from '@prisma/client';
import { processPayment, PaymentStatus } from '../utils/payment-processor.util'; 

import { uploadFile } from '../utils/file-storage.util'; // Utility for S3/GCS upload



// Set inspection period to 3 days (in milliseconds)
const INSPECTION_PERIOD_MS = 3 * 24 * 60 * 60 * 1000; 

interface TransactionUpdates {
    status?: TransactionStatus;
    trackingNumber?: string;
    // Assuming File is a generic representation of file data from controller/middleware
    proofOfShipment?: any; 
}

// #-------------------------------------------Main Business Logic------------------------------------------------

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
        // 1. Fetch Post, Buyer (current user), and Settings atomically
        prisma.post.findUnique({
            where: { id: postId },
            select: { 
                id: true, 
                authorId: true, 
                price: true, 
                isSoldOut: true, 
                title: true, // Needed for notification context
            }
        }),
        prisma.user.findUnique({
            where: { id: currentAuthUserId },
            select: { 
                id: true, 
                address: true, 
                city: true, 
                zipCode: true,
                email: true // Optional: for payment system
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
    // 2.1. Backoffice setting check
    const enablePayments = settings.enablePayments;
    const canPay = currentUserRole !== UserRole.Member || enablePayments;
    
    if (!canPay) {
        throw new ForbiddenError('Payments are currently disabled.');
    }
    // 2.2. Post must not be sold out
    if (post.isSoldOut) {
        throw new BadRequestError('This item is already sold out.');
    }
    // 2.3. Buyer cannot be the seller
    if (post.authorId === currentAuthUserId) {
        throw new BadRequestError('You cannot purchase your own item.');
    }
    // 2.4. Buyer must have shipping address set
    if (!buyer.address || !buyer.city || !buyer.zipCode) {
        throw new BadRequestError('Please complete your shipping address before proceeding with a purchase.');
    }

    // --- 3. Payment Processing (External Call) ---
    const itemPrice = post.price || 0;
    const totalAmount = itemPrice + deliveryFee; //platform fee not included yet.

    // Call the external utility
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

        const transactionCreateData = {
                // ✅ FIX: Use full connect objects for relational fields
                post: { connect: { id: postId } }, 
                buyer: { connect: { id: currentAuthUserId } }, 
                seller: { connect: { id: post.authorId } }, 
                
                itemPrice: itemPrice,
                deliveryFee: deliveryFee,
                totalAmount: totalAmount,
                status: transactionStatus, // Use determined enum status
                paymentReference: paymentResult.reference,
                failureReason: paymentResult.failureReason,
                shippingAddress: `${buyer.address}, ${buyer.city}, ${buyer.zipCode}`,
    
        };
                const createdTransaction = await tx.transaction.create({
                    data: transactionCreateData as unknown as Prisma.TransactionCreateInput
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




/**
 * API: Update Transaction
 * @description Updates the status of a transaction based on the authorized user and business rules.
 */
export const updateTransaction = async (
    transactionId: string, 
    updates: TransactionUpdates,
    currentAuthUserId: string,
    currentUserRole: UserRole
): Promise<Transaction> => {
    
    // 1. Fetch the transaction and its parties
    const transaction = await prisma.transaction.findUnique({
        where: { id: transactionId },
        select: { 
            id: true, 
            buyerId: true, 
            sellerId: true, 
            status: true,
            postId: true 
        }
    });

    if (!transaction) {
        throw new NotFoundError('Transaction not found.');
    }

    // Determine user roles in the transaction
    const isBuyer = transaction.buyerId === currentAuthUserId;
    const isSeller = transaction.sellerId === currentAuthUserId;
    const isAdmin = currentUserRole === UserRole.Admin || currentUserRole === UserRole.SuperAdmin;

    // Authorization: User must be a party to the transaction or an Admin
    if (!isBuyer && !isSeller && !isAdmin) {
        throw new ForbiddenError('You do not have permission to update this transaction.');
    }

    // 2. Prepare the update data and perform access control based on status change

    const { status, trackingNumber, proofOfShipment } = updates;
    let updateData: Prisma.TransactionUpdateInput = {};
    let isAtomicUpdateRequired = false;
    let notificationType: string | null = null;
    let recipientId: string | null = null;
    
    // Process status change logic
    if (status) {
        // --- A. Status change to 'Completed' (ONLY by Buyer or Admin) ---
        if (status === TransactionStatus.Completed) {
            if (!isBuyer && !isAdmin) {
                throw new ForbiddenError('Only the buyer or an administrator can mark a transaction as Completed.');
            }
            if (transaction.status !== TransactionStatus.Delivered) {
                 throw new BadRequestError('Transaction must be in "Delivered" status to be marked "Completed".');
            }

            updateData.status = TransactionStatus.Completed;
            updateData.completedAt = new Date();
            isAtomicUpdateRequired = true; // Requires post update as well
            notificationType = 'TRANSACTION_COMPLETED';
            recipientId = transaction.sellerId; // Notify seller (funds released)

        // --- B. Status change to 'Shipped' (ONLY by Seller or Admin) ---
        } else if (status === TransactionStatus.Shipped) {
            if (!isSeller && !isAdmin) {
                throw new ForbiddenError('Only the seller or an administrator can mark a transaction as Shipped.');
            }
            if (transaction.status !== TransactionStatus.InEscrow) {
                 throw new BadRequestError('Transaction must be in "InEscrow" status to be marked "Shipped".');
            }
            
            // 2.1. Handle proof of shipment file upload
            let shippingProofUrl: string | null = null; // Initialize as null

            if (proofOfShipment) {
                // Assuming uploadFile returns a string (the URL)
                shippingProofUrl = await uploadFile(proofOfShipment, 'shipment-proofs'); 
            }

            updateData.status = TransactionStatus.Shipped;
            updateData.shippedAt = new Date();
            if (trackingNumber) updateData.shippingProof = shippingProofUrl;         
            if (shippingProofUrl) updateData.shippingProofUrl = shippingProofUrl;

            notificationType = 'TRANSACTION_SHIPPED';
            recipientId = transaction.buyerId; // Notify buyer

        // --- C. Status change to 'Delivered' (Admin/Webhook or Seller) ---
        } else if (status === TransactionStatus.Delivered) {
            if (!isAdmin && !isSeller) { 
                // Typically from webhook, but allowing seller/admin for manual override/update
                throw new ForbiddenError('Only the seller or an administrator can mark a transaction as Delivered.');
            }

            const inspectionPeriodEnds = new Date(Date.now() + INSPECTION_PERIOD_MS);
            
            updateData.status = TransactionStatus.Delivered;
            updateData.deliveredAt = new Date();
            updateData.inspectionPeriodEnds = inspectionPeriodEnds;

            notificationType = 'TRANSACTION_DELIVERED';
            recipientId = transaction.buyerId; // Notify buyer
            
        // --- D. Other Status Changes (Disputed, Cancelled, Pending) ---
        } else if (status === TransactionStatus.Cancelled || status === TransactionStatus.Disputed) {
            // These statuses typically have separate dedicated API endpoints or are admin-only
            if (!isAdmin) {
                 throw new ForbiddenError(`Status update to ${status} requires a dedicated endpoint or administrator privileges.`);
            }
            updateData.status = status;
        } else {
            // No other statuses should be settable via this generic endpoint
             throw new BadRequestError(`Cannot directly set status to ${status} via this endpoint.`);
        }
    } else {
        // Allow updating trackingNumber/proofOfShipment without changing status
        if (trackingNumber) {
            if (!isSeller && !isAdmin) {
                throw new ForbiddenError('Only the seller or an administrator can update tracking information.');
            }
            updateData.trackingNumber = trackingNumber;
        }
        // Allow updating only shippingProof without changing status (if a file was uploaded)
        if (proofOfShipment) {
            if (!isSeller && !isAdmin) {
                throw new ForbiddenError('Only the seller or an administrator can update shipping information.');
            }
            const shippingProofUrl = await uploadFile(proofOfShipment, 'shipment-proofs');
            // ✅ FIX: Use the correct schema name 'shippingProof'
            updateData.shippingProof = shippingProofUrl; 
        }
    }
    
    // If no updates were requested, throw an error
    if (Object.keys(updateData).length === 0) {
        throw new BadRequestError('No valid update fields provided.');
    }

    // 3. Perform the Update (Atomic if status is 'Completed')

    let updatedTransaction: Transaction;

    if (isAtomicUpdateRequired) {
        // 3.1. Atomic Update (For Status: Completed)
        const [trans, post] = await prisma.$transaction([
            prisma.transaction.update({
                where: { id: transactionId },
                data: updateData,
            }),
            prisma.post.update({
                where: { id: transaction.postId },
                data: { isSoldOut: true },
            }),
        ]);
        updatedTransaction = trans as unknown as Transaction;
    } else {
        // 3.2. Standard Update
        updatedTransaction = await prisma.transaction.update({
            where: { id: transactionId },
            data: updateData,
        }) as unknown as Transaction;
    }

    // 4. Side Effects (Notifications & Realtime)

    // 4.1. Notification (if required)
    if (notificationType && recipientId) {
        queueJob('SEND_NOTIFICATION', {
            type: notificationType,
            recipientId: recipientId,
            details: { transactionId: updatedTransaction.id, postId: updatedTransaction.postId }
        });
    }

    // 4.2. Realtime Update
    // queueJob('EMIT_REALTIME_UPDATE', { 
    //     event: 'transactionUpdate', 
    //     recipients: [updatedTransaction.buyerId, updatedTransaction.sellerId], 
    //     data: updatedTransaction 
    // });

    return updatedTransaction;
};
