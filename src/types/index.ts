// src/types/index.ts

// --- Best Practice: Import types directly from the Prisma Client ---
// Assuming your Prisma model is named 'User' and 'BankAccounts'
import { User as PrismaUser, 
        BankAccount as PrismaBankAccount, 
        NotificationType as PrismaNotificationType,
        Transaction as PrismaTransaction,
        Review as PrismaReview,
        Post as PrismaPost,
        Comment as PrismaComment, 
        PostCondition,
        Transaction as PrismaTransaction
       } from '@prisma/client';

// Re-export the core types for use across the application
export type User = PrismaUser;
export type BankAccount = PrismaBankAccount;
export type NotificationType = PrismaNotificationType;
export type Transaction = PrismaTransaction;
export type Review = PrismaReview;
export type Comment = PrismaComment;
export type Transaction = PrismaTransaction;

// --- Define Custom Types for API Responses/Requests ---


// The definitive type for the authenticated user context
export interface AuthUser {
    id: string;
    role: string; 
    isBanned: boolean; 
    hasBankAccount: boolean; 
}

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


// Define the Post interface, making sure to use the correct fields
export interface Post extends Omit<PrismaPost, 'createdAt' | 'updatedAt'> {
    // Override/Ensure fields used in custom logic are present
    timestamp: Date;
    lastActivityTimestamp: Date;
    likesCount: number;
    commentsCount: number;
    // Add computed scores for the in-memory sorting paths
    trendingScore?: number; 
    engagementScore?: number;
}


export interface GetPostsFilters {
    viewMode: 'discussions' | 'adverts';
    sortMode?: 'top' | 'trending' | 'new';
    advertSort?: 'newest' | 'price_asc' | 'price_desc';
    limit?: number;
    offset?: number;
    minPrice?: number;
}


export interface CreatePostPayload {
    title: string;
    content: string;
    price?: number;
    categoryId: string;
    media?: any[]; // Using 'any' for the JSON structure, but should be a dedicated type
    brand?: string;
    condition?: PostCondition;
    deliveryOptions?: any; // Using 'any' for the JSON structure
    quantity?: number;
}


export interface EssentialBackofficeSettings {
    enablePostCreation: boolean;
    enableAdvertisements: boolean;
    maintenanceMode:      Boolean;
    enablePayments:       Boolean;
    enableSignups:        Boolean;
    enableLogins:         Boolean;
    enableCommenting:     Boolean;
    enableLikes:          Boolean;
    enableFollowing:      Boolean;
    enableChats:          Boolean;
    enableCalling:        Boolean;
    enableDisputes:       Boolean;
}
