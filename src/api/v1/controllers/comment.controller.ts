import { Request, Response, NextFunction } from 'express';
import { addComment, editComment, deleteComment, likeComment, dislikeComment } from '../../../services/comment.service';
import { AuthUser } from '../../../types'; 
import { UserRole } from '@prisma/client';
// Custom interface for authenticated request
interface AuthRequest extends Request {
    userId?: string;
    userRole?: UserRole; 
}


// Add comment Controller
export const addCommentController = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const postId = req.params.postId;
        const { content, media, parentId } = req.body; // parentId is optional
        const currentAuthUserId = req.userId; 
        const currentUserRole = req.userRole; 

        if (!currentAuthUserId || !currentUserRole) {
            return res.status(403).json({ message: 'Authentication required.' });
        }

        const newComment = await addComment(
            postId, 
            { content, media }, 
            parentId || null,
            currentAuthUserId,
            currentUserRole
        );

        // Realtime: Emit new comment event
        // io.emit(`newComment:${postId}`, newComment);

        // Success response
        return res.status(201).json(newComment);

    } catch (error: any) {
        next(error);
    }
};


// Edit comment Controller

export const editCommentController = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const { postId, commentId } = req.params;
        // Body parameter is typically camelCase, but spec used 'newContent'
        const { newContent } = req.body; 
        const currentAuthUserId = req.userId; 

        if (!currentAuthUserId) {
            return res.status(403).json({ message: 'Authentication required.' });
        }

        const updatedComment = await editComment(
            postId, 
            commentId, 
            newContent,
            currentAuthUserId
        );

        // Realtime: Emit comment update event
        // io.emit(`commentUpdate:${postId}`, updatedComment);

        // Success response
        return res.status(200).json(updatedComment);

    } catch (error: any) {
        next(error);
    }
};


// Delete comment Controller
export const deleteCommentController = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const { postId, commentId } = req.params;
        const currentAuthUserId = req.userId;
        const currentUserRole = req.userRole;

        if (!currentAuthUserId || !currentUserRole) {
            return res.status(403).json({ message: 'Authentication required.' });
        }

        await deleteComment(
            postId, 
            commentId, 
            currentAuthUserId,
            currentUserRole
        );

        // Realtime: Emit comment delete event
        // io.emit(`commentDelete:${postId}`, commentId);

        // Success response for DELETE is 204 No Content
        return res.status(204).send();

    } catch (error: any) {
        next(error);
    }
};





// --- Like Comment Controller ---

export const likeCommentController = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const { postId, commentId } = req.params;
        const currentAuthUserId = req.userId; 
        const currentUserRole = req.userRole; 

        if (!currentAuthUserId || !currentUserRole) {
            return res.status(403).json({ message: 'Authentication required.' });
        }

        const result = await likeComment(postId, commentId, currentAuthUserId, currentUserRole);

        // Realtime: This event would typically be emitted here
        // io.emit(`commentUpdate:${postId}`, result); 

        return res.status(200).json(result);

    } catch (error: any) {
        next(error);
    }
};

// --- Dislike Comment Controller ---

export const dislikeCommentController = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const { postId, commentId } = req.params;
        const currentAuthUserId = req.userId; 
        const currentUserRole = req.userRole; 

        if (!currentAuthUserId || !currentUserRole) {
            return res.status(403).json({ message: 'Authentication required.' });
        }

        const result = await dislikeComment(postId, commentId, currentAuthUserId, currentUserRole);

        // Realtime: Emit event on success
        // io.emit(`commentUpdate:${postId}`, result); 

        return res.status(200).json(result);

    } catch (error: any) {
        next(error);
    }
};
