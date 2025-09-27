import { Router } from 'express';
import { authMiddleware } from '../../../middlewares/auth.middleware';
import { getTransactionsController, createTransactionController, updateTransactionController } from '../controllers/transaction.controller';

//multer for file handling
import multer from 'multer'; 

// 1. Configure storage: Using memoryStorage is standard for passing the file buffer 
// to a cloud storage service (like S3, Google Cloud Storage, etc.) from the service layer.
const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 } // Example: 5MB limit
}); 


const router = Router();

//  GET USER TRANSACTIONS
// Endpoint: GET /api/transactions
router.get('/', authMiddleware, getTransactionsController); 


// Endpoint: POST /api/transactions
router.post('/', authMiddleware, createTransactionController); 

// UPDATE TRANSACTION STATUS (PUT /api/transactions/{transactionId})
// Middleware: 'upload.single('proofOfShipment')' extracts the file from the request
router.put('/:transactionId', authMiddleware, upload.single('proofOfShipment'), updateTransactionController); 

export default router;
