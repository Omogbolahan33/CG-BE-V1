// src/app.ts

import express, { Application, Request, Response, NextFunction } from 'express';
import { json } from 'body-parser';
import cors from 'cors'; // You'd typically install and use 'cors'
import v1Router from './api/v1/routes'; // We will define this index file

const app: Application = express();

// --- Global Middleware Setup ---
app.use(json()); // Body parsing middleware
app.use(cors({ origin: '*' })); // Configure CORS appropriately for production

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
