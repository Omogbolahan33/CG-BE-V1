import { Router } from 'express';
import { authMiddleware } from '../../../middlewares/auth.middleware';
import { addCommentController, editCommentController } from '../controllers/comment.controller'; 

const router = Router({ mergeParams: true });

// ADD COMMENT
// Endpoint: POST /api/v1/posts/:postId/comments
router.post('/:postId/comments', authMiddleware, addCommentController); 

// EDIT COMMENT
// Endpoint: PUT /:postId/comments/:commentId
// This route is relative to the mount point of the comment router in post.routes.ts
router.put('/:commentId', authMiddleware, editCommentController); 

export default router;
