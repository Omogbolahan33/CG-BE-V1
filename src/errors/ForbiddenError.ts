// src/errors/ForbiddenError.ts

export class ForbiddenError extends Error {
    statusCode: number;

    /**
     * Custom error for 403 Forbidden responses.
     * Use when the user is authenticated but lacks permission (e.g., role restriction, feature disabled, or blocking).
     * @param message The user-facing message.
     * @param statusCode The HTTP status code (defaults to 403).
     */
    constructor(message: string, statusCode = 403) {
        // Call the parent (Error) constructor
        super(message);
        
        // Set the name for easier identification in logs/debugging
        this.name = 'ForbiddenError';
        
        // Set the status code for the global error handler
        this.statusCode = statusCode;
        
        // Standard practice to maintain a clean stack trace
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, ForbiddenError);
        }
    }
}
