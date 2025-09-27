import { Router } from 'express';
import { getPostsController, getPostDetailsController,createPostController  } from '../controllers/post.controller';
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

export default router;
