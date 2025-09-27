import { Router } from 'express';
import { authMiddleware } from '../../../middleware/auth.middleware';
import { addCommentController } from '../controllers/comment.controller'; 

const router = Router({ mergeParams: true });

//ADD COMMENT
// Endpoint: POST /api/v1/posts/:postId/comments
router.post('/:postId/comments', authMiddleware, addCommentController); 

export default router;
