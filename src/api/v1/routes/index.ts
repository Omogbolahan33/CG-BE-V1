// src/api/v1/routes/index.ts (Updated)

import { Router } from 'express';


// import userRoutes from './user.route';
import authRoutes from './auth.route'; 
import userRouter from './user.routes'; 
import postRoutes from './post.routes';
import commentRouter from './comment.routes';
import transactionRouter from './transaction.routes'; 

const v1Router = Router();

// AUTHENTICATION ROUTES
// Mounts all routes from auth.routes.ts under the path /api/v1/auth
v1Router.use('/auth', authRoutes); 

// USER ROUTES
// Mounts all routes from user.routes.ts under the path /api/v1/users
// This makes the endpoint: GET /api/v1/users/me
v1Router.use('/users', userRouter);

// POST ROUTES
// Mounts all routes from post.routes.ts under the path /api/v1/posts
v1Router.use('/posts', postRoutes);

// COMMENT ROUTES
// Mounts all routes from comment.routes.ts under the path /api/v1/posts
v1Router.use('/:postId/comments', commentRouter);

// TRANSACTION ROUTES
// Mounts all routes from transaction.routes.ts under the path /api/v1/posts
v1Router.use('/api/transactions', transactionRouter); 

export default v1Router;
