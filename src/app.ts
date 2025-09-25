// src/app.ts

import express, { Application, Request, Response, NextFunction } from 'express';
import { json } from 'body-parser';
import cors from 'cors'; // You'd typically install and use 'cors'
import v1Router from './api/v1/routes'; // We will define this index file
import cookieParser from 'cookie-parser';

import { AuthenticationError } from './errors/AuthenticationError'; 


const app: Application = express();

// -------------------------------------------------------------
// --- ENVIRONMENT-SPECIFIC CONFIGURATION ---

// Set this to the exact domain where your frontend app is hosted (e.g., 'https://your-frontend-app.com')
// Use a list if you have multiple domains (e.g., development and production)
const allowedOrigins = [
    'http://localhost:3000', 
    'https://aistudio.google.com', 
    'https://0z57rgyh0m3r4xfj7sl00eygmiymd0unimkffhkn6zzq1twd26-h807678934.scf.usercontent.goog',
    'https://web.postman.co'
];

const corsOptions: cors.CorsOptions = {
    // 1. Specify which origins are allowed to send requests
    origin: (origin, callback) => {
        // Allow requests with no origin (like mobile apps or postman requests)
        if (!origin) return callback(null, true); 
        // Allow if the origin is in our list
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'), false);
        }
    },
    // 2. IMPORTANT: Must be true for the browser to send and receive HttpOnly cookies (credentials)
    credentials: true,
    // Specify allowed methods and headers
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    allowedHeaders: 'Content-Type,Authorization',
};

// --- Global Middleware Setup ---
app.use(json()); // Body parsing middleware
app.use(cookieParser()); // Cookie parsing middleware (needed for HttpOnly)
app.use(cors(corsOptions)); // Apply the custom CORS configuration


// --- API Router Setup ---
// The main entry for all v1 API routes
app.use('/api/v1', v1Router);

// --- Health Check / Root Route ---
app.get('/', (req: Request, res: Response) => {
  res.status(200).send({
    message: 'Social Marketplace API is Running!',
    version: 'v1'
  });
});

// --- Global Error Handler (Placeholder for best practice) ---
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error(err.stack); // Log the error stack to the server console
  const statusCode = (err as any).statusCode || 500;
  res.status(statusCode).json({
    message: 'An unexpected error occurred.',
    error: err.message,
    statusCode: statusCode
  });
});


export default app;
