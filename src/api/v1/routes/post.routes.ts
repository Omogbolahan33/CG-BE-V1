import { Router } from 'express';
import { getPostsController, getPostDetailsController} from '../controllers/post.controller';

const router = Router();

// Endpoint: GET /api/v1/posts
router.get('/', getPostsController); 

// Endpoint: GET /api/v1/posts/:postId
// Fetches a single post's details
router.get('/:postId', getPostDetailsController);

export default router;
