import { Router } from 'express';
import { authMiddleware } from '../middleware/auth.middleware';
import { getTransactionsController } from '../controllers/transaction.controller';

const router = Router();

//  GET USER TRANSACTIONS
// Endpoint: GET /api/transactions
router.get('/', authMiddleware, getTransactionsController); 

export default router;
