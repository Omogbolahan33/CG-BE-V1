import { Router } from 'express';
import { authMiddleware } from '../../../middlewares/auth.middleware';
// Import the new controller function
import { getCurrentUserController, 
        getUserProfileController, 
        updateUserSettingsController, 
        updateUserBankAccountController, 
        requestFollowController,
       cancelFollowRequestController,acceptFollowRequestController } from '../controllers/auth.controller'; 

const router = Router();

// Route for getting the currently authenticated user
router.get('/me', authMiddleware, getCurrentUserController); 

// Route for getting any user's public profile by ID <-- NEW ROUTE
// Endpoint: GET /api/v1/users/{userId}
router.get('/:userId', authMiddleware, getUserProfileController); 

// Route for getting any user's public profile by ID
// Endpoint: GET /api/v1/users/{userId}
router.get('/:userId', authMiddleware, getUserProfileController); 

// Route for UPDATING the user's bank account
// Endpoint: PUT /api/v1/users/me/bank-account
router.put('/me/bank-account', authMiddleware, updateUserBankAccountController);

// Route for requesting to follow a user
// Endpoint: POST /api/v1/users/{userId}/follow
router.post('/:userId/follow', authMiddleware, requestFollowController); 

// Route for cancelling a follow request
// Endpoint: DELETE /api/v1/users/{userId}/follow-request
router.delete('/:userId/follow-request', authMiddleware, cancelFollowRequestController);

// Route for accepting a follow request <-- NEW ROUTE
// Endpoint: POST /api/v1/users/follow-requests/{requesterId}/accept
router.post('/follow-requests/:requesterId/accept', authMiddleware, acceptFollowRequestController);


export default router;
