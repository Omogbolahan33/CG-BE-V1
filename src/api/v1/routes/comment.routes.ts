import { Router } from 'express';
import { authMiddleware } from '../middleware/auth.middleware';
// Update named imports to include the new controller
import { addCommentController } from '../controllers/comment.controller'; // Adjust import path if using a separate comment.controller.ts

const router = Router();

ADD COMMENT
// Endpoint: POST /api/v1/posts/:postId/comments
router.post('/:postId/comments', authMiddleware, addCommentController); 

export default router;
