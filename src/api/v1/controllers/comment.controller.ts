import { Request, Response, NextFunction } from 'express';
import { addComment } from '../../../services/comment.service';
import { AuthUser } from '../types'; 
import { UserRole } from '@prisma/client';

// Custom interface for authenticated request
interface AuthRequest extends Request {
    userId?: string;
    userRole?: UserRole; 
}

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

