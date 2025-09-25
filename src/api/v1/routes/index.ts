// src/api/v1/routes/index.ts (Updated)

import { Router } from 'express';
import userRoutes from './user.route';
import authRoutes from './auth.route'; // <--- NEW IMPORT

const v1Router = Router();

// Mount all specific module routes here
v1Router.use('/users', userRoutes);
v1Router.use('/auth', authRoutes); // <--- NEW MOUNT POINT
// v1Router.use('/posts', postRoutes);
// v1Router.use('/transactions', transactionRoutes);

export default v1Router;
