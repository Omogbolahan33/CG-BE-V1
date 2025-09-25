export class BadRequestError extends Error {
    statusCode: number;

    constructor(message: string, statusCode = 400) {
        super(message);
        this.name = 'BadRequestError';
        this.statusCode = statusCode;
        // Optionally capture stack trace
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, BadRequestError);
        }
    }
}
