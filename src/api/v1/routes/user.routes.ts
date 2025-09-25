import { Router } from 'express';
import { authMiddleware } from '../../../middlewares/auth.middleware';
// Import the new controller function
import { getCurrentUserController, getUserProfileController, updateUserSettingsController, updateUserBankAccountController, requestFollowController } from '../controllers/auth.controller'; 

const router = Router();

// Route for getting the currently authenticated user
router.get('/me', authMiddleware, getCurrentUserController); 

// Route for getting any user's public profile by ID <-- NEW ROUTE
// Endpoint: GET /api/v1/users/{userId}
router.get('/:userId', authMiddleware, getUserProfileController); 

// Route for getting any user's public profile by ID
// Endpoint: GET /api/v1/users/{userId}
router.get('/:userId', authMiddleware, getUserProfileController); 

// Route for UPDATING the user's bank account <-- NEW ROUTE
// Endpoint: PUT /api/v1/users/me/bank-account
router.put('/me/bank-account', authMiddleware, updateUserBankAccountController);

// Route for requesting to follow a user <-- NEW ROUTE
// Endpoint: POST /api/v1/users/{userId}/follow
router.post('/:userId/follow', authMiddleware, requestFollowController); 

export default router;
