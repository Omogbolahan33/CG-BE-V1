import { Router } from 'express';
import { authMiddleware } from '../../../middlewares/auth.middleware';
import { getTransactionsController, createTransactionController } from '../controllers/transaction.controller';

const router = Router();

//  GET USER TRANSACTIONS
// Endpoint: GET /api/transactions
router.get('/', authMiddleware, getTransactionsController); 


// Endpoint: POST /api/transactions
router.post('/', authMiddleware, createTransactionController); 


export default router;
