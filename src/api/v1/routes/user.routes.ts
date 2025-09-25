import { Router } from 'express';
import { authMiddleware } from '../../../middlewares/auth.middleware';
// Import the new controller function
import { getCurrentUserController } from '../controllers/auth.controller'; 

const router = Router();

// Route for getting the currently authenticated user
router.get('/me', authMiddleware, getCurrentUserController); 

export default router;
