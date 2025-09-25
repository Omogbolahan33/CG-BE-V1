// src/errors/ConflictError.ts

export class ConflictError extends Error {
    statusCode: number;

    constructor(message: string, statusCode = 409) {
        super(message);
        this.name = 'ConflictError';
        this.statusCode = statusCode;
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, ConflictError);
        }
    }
}
