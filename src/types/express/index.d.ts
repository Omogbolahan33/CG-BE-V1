// src/types/express/index.d.ts

import { AuthUser } from '../index';
// Import the base Request type from Express
import * as express from 'express';

declare global {
  namespace Express {
    // Extend the built-in Request interface
    interface Request {
      // ⚠️ Use the full user object property for best practice
      user?: AuthUser;
      
      // Keep legacy properties defined by the middleware for compatibility
      userId?: string;
      role?: string;
      token?: string;
    }
  }
}
