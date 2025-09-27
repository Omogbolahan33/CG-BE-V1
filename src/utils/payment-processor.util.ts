// src/utils/payment-processor.util.ts

/**
 * Defines the result structure returned by the payment processor.
 * Status can be 'SUCCESS', 'FAILURE', or 'PENDING' (for async flows).
 */
export type PaymentStatus = 'SUCCESS' | 'FAILURE' | 'PENDING';

export interface PaymentResult {
    status: PaymentStatus;
    reference: string;
    failureReason: string | null;
}

/**
 * Mocks the external API call to a payment provider (e.g., Paystack, Stripe).
 * This function simulates success, failure, or a pending state.
 * * @param amount The total transaction amount to process.
 * @returns A promise resolving to the PaymentResult object.
 */
export const processPayment = async (amount: number): Promise<PaymentResult> => {
    // Simulate network latency
    await new Promise(resolve => setTimeout(resolve, 50)); 
    
    // Adjust the probabilities for demonstration
    const random = Math.random();

    if (random < 0.7) { // 70% chance of success
        return {
            status: 'SUCCESS',
            reference: `REF_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
            failureReason: null,
        };
    } else if (random < 0.9) { // 20% chance of failure
        return {
            status: 'FAILURE',
            reference: `REF_${Date.now()}_FAIL`,
            failureReason: 'Card declined by issuing bank or payment gateway.',
        };
    } else { // 10% chance of pending (e.g., waiting for bank transfer confirmation)
        return {
            status: 'PENDING',
            reference: `REF_${Date.now()}_PEND`,
            failureReason: 'Transaction is awaiting external confirmation.',
        };
    }
};
