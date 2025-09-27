// src/types/index.ts

// --- Best Practice: Import types directly from the Prisma Client ---
// Assuming your Prisma model is named 'User' and 'BankAccounts'
import { User as PrismaUser, 
        BankAccount as PrismaBankAccount, 
        NotificationType as PrismaNotificationType,
        Transaction as PrismaTransaction,
        Review as PrismaReview,
        Post as PrismaPost
       } from '@prisma/client';

// Re-export the core types for use across the application
export type User = PrismaUser;
export type BankAccount = PrismaBankAccount;
export type NotificationType = PrismaNotificationType;
export type Transaction = PrismaTransaction;
export type Review = PrismaReview;

// --- Define Custom Types for API Responses/Requests ---

// Define the fields that are always sensitive and MUST be omitted from public responses.
export type SensitiveUserFields = 
    | 'password' 
    | 'verificationOtp' 
    | 'verificationOtpExpiry' 
    | 'passwordResetOtp' 
    | 'passwordResetOtpExpiry'
    | 'banReason' 
    | 'banStartDate'; 

// Define the fields that should be omitted only for public profile viewing (privacy).
export type PrivateUserFields = 
    | 'password' 
    | 'email' 
    | 'address' 
    | 'city' 
    | 'zipCode' 
    | 'bankAccount' // Note: This is a relation, but included here for type definition
    | 'verificationOtp' 
    | 'verificationOtpExpiry' 
    | 'passwordResetOtp' 
    | 'passwordResetOtpExpiry';
    
export type PublicUserProfile = Omit<User, PrivateUserFields>;

export interface UpdateBankAccountPayload {
  password: string; // For re-authentication
  accountName: string;
  accountNumber: string;
  bankName: string;
  // Add other required BankAccount fields
}

// Define the shape of the login credentials
export interface LoginCredentials {
  identifier: string;
  password: string;
  // Metadata fields for logging (often passed from the controller)
  ip?: string;
  userAgent?: string;
}
// Define the expected successful response type
export interface LoginResponse {
  user: Omit<User, SensitiveUserFields>;
  token: string;
}

// Define the shape of the signup credentials
export interface SignUpCredentials {
  username: string;
  email: string;
  password: string;
}
// Define the expected successful response type
export interface SignUpResponse {
    user: Omit<User, SensitiveUserFields>; 
    token: string;
}
// Define the shape of the verifyEmail credentials
export interface VerifyEmailByOtpCredentials {
  userId: string;
  otp: string;
}

// Define the shape of the ResetPassword credentials
export interface ResetPasswordCredentials {
  email: string;
  otp: string;
  newPassword: string;
}

// Define the required structure for the bank account update API request body
export interface UpdateBankAccountPayload {
  password: string; // Required for re-authentication
  accountName: string;
  accountNumber: string;
  bankName: string;
  // Add any other required BankAccount fields here (e.g., routingNumber, swiftCode)
}

export interface AddReviewPayload {
    rating: number; // e.g., 1 to 5
    comment: string;
    transactionId?: string;
}

export interface ReportUserPayload {
    reportedUserId: string;
    reason: string;
    details: string;
    attachmentUrl?: string; // Changed from File to URL string for API consistency
}


// Define the Post interface matching the select fields in the service
export interface Post extends PrismaPost {
    // No need to add custom fields unless they were added in the service map.
    // If you add computed fields (like 'trendingScore') in the service, you'd add them here
    // trendingScore?: number; 
    // engagementScore?: number;
}
