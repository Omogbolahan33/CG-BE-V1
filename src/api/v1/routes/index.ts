// src/api/v1/routes/index.ts (Updated)

import { Router } from 'express';


// import userRoutes from './user.route';
import authRoutes from './auth.route'; 
import userRouter from './user.routes'; 

const v1Router = Router();

// AUTHENTICATION ROUTES
// Mounts all routes from auth.routes.ts under the path /api/v1/auth
v1Router.use('/auth', authRouter); 

// USER ROUTES
// Mounts all routes from user.routes.ts under the path /api/v1/users
// This makes the endpoint: GET /api/v1/users/me
v1Router.use('/users', userRouter);

export default v1Router;
