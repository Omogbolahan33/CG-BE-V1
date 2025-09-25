// src/utils/crypto.util.ts

import * as crypto from 'crypto';

// --- SECURITY CRITICAL CONFIGURATION ---
// In a real application, these MUST be pulled securely from environment variables, 
// a dedicated secrets manager (like AWS KMS, Azure Key Vault), or an HSM.
// The key should be 32 bytes (256 bits) for AES-256.
const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY || 'a'.repeat(32), 'utf8'); 
// The IV should be 16 bytes. It's often generated randomly and stored alongside the ciphertext.
const IV_LENGTH = 16; 
const ALGORITHM = 'aes-256-cbc';
// ----------------------------------------

/**
 * Encrypts data using AES-256-CBC and prepends the IV to the ciphertext.
 * This simulates the robust structure required for production encryption.
 * @param data The plaintext string to encrypt.
 * @returns A string containing the IV and ciphertext, separated by a colon, both encoded in hex.
 */
export const encryptData = (data: string): string => {
    // 1. Generate a random IV for security (crucial for rotation/unique encryption)
    const iv = crypto.randomBytes(IV_LENGTH); 
    
    // 2. Create the cipher instance
    const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
    
    // 3. Encrypt the data
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // 4. Return the IV and the encrypted data, joined by a colon (e.g., "iv:ciphertext")
    // This allows the decrypt function to retrieve the unique IV.
    return iv.toString('hex') + ':' + encrypted;
};

/**
 * Decrypts data previously encrypted with encryptData.
 * @param encryptedText The encrypted string (format: "iv:ciphertext").
 * @returns The original plaintext string.
 */
export const decryptData = (encryptedText: string): string => {
    try {
        const parts = encryptedText.split(':');
        
        if (parts.length !== 2) {
            throw new Error("Invalid encrypted format.");
        }
        
        const iv = Buffer.from(parts[0], 'hex');
        const encrypted = parts[1];
        
        if (iv.length !== IV_LENGTH) {
            throw new Error("Invalid IV length.");
        }

        // 1. Create the decipher instance
        const decipher = crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
        
        // 2. Decrypt the data
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
    } catch (error) {
        console.error("Decryption failed:", error);
        // In a production environment, you would log this failure and throw a 
        // generic error (e.g., an InternalServerError) to the client.
        return ''; // Return empty or throw an error to prevent using corrupted data
    }
};
