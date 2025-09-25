// src/types/index.ts

// --- Best Practice: Import types directly from the Prisma Client ---
// Assuming your Prisma model is named 'User' and 'BankAccounts'
import { User as PrismaUser, BankAccounts as PrismaBankAccount  } from '@prisma/client';

// Re-export the core types for use across the application
export type User = PrismaUser;
export type BankAccount = PrismaBankAccount;

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
