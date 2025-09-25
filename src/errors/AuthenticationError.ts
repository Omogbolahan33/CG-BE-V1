/**
 * Custom error class for authentication failures (HTTP 401/403).
 * This allows us to catch a specific type of error in the controller
 * and return a standardized HTTP response.
 */
export class AuthenticationError extends Error {
    // Standard HTTP status code for this error type
    public statusCode: number;

    constructor(message: string, statusCode: number = 401) {
        // Call the base Error class constructor
        super(message);
        
        // Set the status code for HTTP response
        this.statusCode = statusCode;
        
        // Set the prototype explicitly (important for TypeScript/Node.js)
        Object.setPrototypeOf(this, AuthenticationError.prototype);
    }
}
