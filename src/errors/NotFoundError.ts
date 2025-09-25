// src/errors/NotFoundError.ts

export class NotFoundError extends Error {
    statusCode: number;

    /**
     * Custom error for 404 Not Found responses.
     * @param message The user-facing message (e.g., "User not found").
     * @param statusCode The HTTP status code (defaults to 404).
     */
    constructor(message: string, statusCode = 404) {
        // Call the parent (Error) constructor
        super(message);
        
        // Set the name for easier identification in logs/debugging
        this.name = 'NotFoundError';
        
        // Set the status code for the global error handler
        this.statusCode = statusCode;
        
        // This is a standard practice to maintain a clean stack trace
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, NotFoundError);
        }
    }
}
