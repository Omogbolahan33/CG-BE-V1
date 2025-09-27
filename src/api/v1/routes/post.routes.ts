import { Router } from 'express';
import { getPostsController } from '../controllers/post.controller';

const router = Router();

// Endpoint: GET /api/v1/posts
router.get('/', getPostsController); 

export default router;
