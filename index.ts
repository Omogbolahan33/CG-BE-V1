import express from 'express';
import cookieParser from 'cookie-parser';
import authRoutes from './src/routes/authRoutes';
import { errorHandler } from './src/middleware/errorHandler';

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use('/api/auth', authRoutes);

app.get('/health', (_, res) => res.json({ status: 'ok' }));

// Must be last
app.use(errorHandler);

export default app;
