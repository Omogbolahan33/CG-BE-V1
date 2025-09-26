import { Router } from 'express';
import { authMiddleware } from '../../../middlewares/auth.middleware';
// Import the new controller function
import { getCurrentUserController, 
        getUserProfileController, 
        updateUserSettingsController, 
        updateUserBankAccountController, 
        requestFollowController,
        cancelFollowRequestController, 
        acceptFollowRequestController, 
        declineFollowRequestController, 
        unfollowUserController, 
        blockUserController, 
        unblockUserController, addReviewController } from '../controllers/auth.controller'; 

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

// Route for declining a follow request <-- NEW ROUTE
// Endpoint: POST /api/v1/users/follow-requests/{requesterId}/decline
router.post('/follow-requests/:requesterId/decline', authMiddleware, declineFollowRequestController);

// Route for to unfollow a user
// Endpoint: /api/v1/users/{userId}/follow
router.delete('/:userId/follow', authMiddleware, unfollowUserController); // DELETE is for unfollowing/removing the relationship <-- UPDATED ROUTE

// Endpoint: /api/v1/users/{userId}/block
// POST is for blocking, DELETE is for unblocking
router.post('/:userId/block', authMiddleware, blockUserController);

// Endpoint: /api/v1/users/{userId}/block
// POST is for unblocking, DELETE is for unblocking
router.delete('/:userId/block', authMiddleware, unblockUserController);

// Route for adding a review <-- NEW ROUTE
// Endpoint: POST /api/v1/users/{userId}/reviews
router.post('/:userId/reviews', authMiddleware, addReviewController);

export default router;
