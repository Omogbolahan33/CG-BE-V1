import { Router } from 'express';
import { authMiddleware } from '../../../middlewares/auth.middleware';
import { addCommentController, 
        editCommentController, 
        deleteCommentController, likeCommentController, dislikeCommentController } from '../controllers/comment.controller'; 

const router = Router({ mergeParams: true });

// ADD COMMENT
// Endpoint: POST /api/v1/posts/:postId/comments
router.post('/:postId/comments', authMiddleware, addCommentController); 

// EDIT COMMENT
// Endpoint: PUT /:postId/comments/:commentId
// This route is relative to the mount point of the comment router in post.routes.ts
router.put('/:commentId', authMiddleware, editCommentController); 

//  DELETE COMMENT
// Endpoint: DELETE /:postId/comments/:commentId
router.delete('/:commentId', authMiddleware, deleteCommentController); 

// LIKE COMMENT
// Endpoint: POST /:postId/comments/:commentId/like
router.post('/:commentId/like', authMiddleware, likeCommentController); 

// DISLIKE COMMENT
// Endpoint: POST /:postId/comments/:commentId/dislike
router.post('/:commentId/dislike', authMiddleware, dislikeCommentController); 

export default router;
