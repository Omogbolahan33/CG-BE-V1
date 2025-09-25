import { Router } from 'express';
import { authMiddleware } from '../../../middlewares/auth.middleware';
// Import the new controller function
import { getCurrentUserController, getUserProfileController } from '../controllers/auth.controller'; 

const router = Router();

// Route for getting the currently authenticated user
router.get('/me', authMiddleware, getCurrentUserController); 

// Route for getting any user's public profile by ID <-- NEW ROUTE
// Endpoint: GET /api/v1/users/{userId}
router.get('/:userId', authMiddleware, getUserProfileController); 


export default router;
