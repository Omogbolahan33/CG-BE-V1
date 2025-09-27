import { Router } from 'express';
import { getPostsController, 
        getPostDetailsController,
        createPostController, 
        updatePostController, 
        deletePostController, 
        likePostController, 
        dislikePostController } from '../controllers/post.controller';
import { authMiddleware } from '../../../middlewares/auth.middleware';

const router = Router();

// Endpoint: GET /api/v1/posts
router.get('/', getPostsController); 

// Endpoint: GET /api/v1/posts/:postId
// Fetches a single post's details
router.get('/:postId', getPostDetailsController);

// Endpoint: POST /api/v1/posts 
// Authorization: CREATE POST Requires user to be logged in (via authMiddleware)
router.post('/', authMiddleware, createPostController);

// Endpoint: PUT /api/v1/posts/:postId
// Authorization: Update POST Requires user to be logged in (via authMiddleware)
router.put('/:postId', authMiddleware, updatePostController); 

// Endpoint: DELETE /api/v1/posts/:postId
// Authorization: User must be logged in
router.delete('/:postId', authMiddleware, deletePostController); 

//  Endpoint LIKE POST
// Endpoint: POST /api/v1/posts/:postId/like
router.post('/:postId/like', authMiddleware, likePostController); 

//  Endpoint DISLIKE POST
// Endpoint: POST /api/v1/posts/:postId/dislike
router.post('/:postId/dislike', authMiddleware, dislikePostController); 

export default router;
