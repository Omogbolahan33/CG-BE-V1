import { UserRole } from '@prisma/client';
import { Request, Response, NextFunction } from 'express';
import { GetPostsFilters, AuthUser, CreatePostPayload } from '../../../types';
import { getPosts, 
        getPostDetails, 
        createPost, 
        updatePost, 
        deletePost, 
        likePost, dislikePost } from '../../../services/post.service'; 
import { ForbiddenError } from '../../../errors/ForbiddenError';

/**
 * API: Get Posts
 * @description Handles the request to fetch posts with filtering and sorting.
 */
export const getPostsController = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { viewMode, sortMode, advertSort, limit, offset, minPrice } = req.query;

        // Basic validation and type conversion
        if (viewMode !== 'discussions' && viewMode !== 'adverts') {
            throw new Error('viewMode is required and must be "discussions" or "adverts".');
        }

        const filters: GetPostsFilters = {
            viewMode: viewMode as 'discussions' | 'adverts',
            sortMode: sortMode as 'top' | 'trending' | 'new',
            advertSort: advertSort as 'newest' | 'price_asc' | 'price_desc',
            limit: limit ? parseInt(limit as string, 10) : undefined,
            offset: offset ? parseInt(offset as string, 10) : undefined,
            minPrice: minPrice ? parseFloat(minPrice as string) : undefined,
        };

        const { posts, total } = await getPosts(filters);

        return res.status(200).json({
            status: 'success',
            message: 'Posts fetched successfully.',
            data: { posts, total },
        });

    } catch (error) {
        next(error);
    }
};



/**
 * API: Get Post Details
 * @description Fetches a single post by ID with nested comments.
 */
export const getPostDetailsController = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { postId } = req.params;

        if (!postId) {
            throw new Error('Post ID is required in the path parameters.');
        }

        const post = await getPostDetails(postId);

        return res.status(200).json({
            status: 'success',
            message: 'Post details fetched successfully.',
            data: post,
        });

    } catch (error) {
        next(error);
    }
};


/**
 * API: Create Post
 * @description Handles the request to create a new post using the authenticated user context.
 */
export const createPostController = async (req: Request, res: Response, next: NextFunction) => {
    try {
        // 🔥 FIX: The req.user property now exists due to the global type extension.
        const authUser = req.user; 
        
        if (!authUser || !authUser.id) {
            throw new ForbiddenError("Authentication context missing.", 401);
        }

        const postData: CreatePostPayload = req.body;
        
        const createdPost = await createPost(postData, authUser);

        return res.status(201).json({
            status: 'success',
            message: 'Post created successfully.',
            data: createdPost,
        });

    } catch (error) {
        next(error); 
    }
};




/**
 * API: Update Post
 * @description Handles the request to create a new post using the authenticated user context.
 */
// Custom interface for authenticated request
interface AuthRequest extends Request {
    userId?: string;
    user?: AuthUser;
}

export const updatePostController = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const postId = req.params.postId;
        const postData = req.body;
        
        const currentAuthUserId = req.userId; 
        const currentUser = req.user; 

        // This should be guaranteed by authMiddleware, but we check defensively
        if (!currentAuthUserId || !currentUser) {
            return res.status(403).json({ message: 'Authentication required.' });
        }

        const updatedPost = await updatePost(
            postId, 
            postData, 
            currentAuthUserId,
            currentUser
        );

        // Success response
        return res.status(200).json({
            status: 'success',
            message: 'Post updated successfully.',
            data: updatedPost
        });

    } catch (error: any) {
        // Delegate error handling to the Express error handler
        next(error);
    }
};



/**
 * API: Delete Post
 * @description Handles the request to create a new post using the authenticated user context.
 */
// Custom interface for authenticated request
interface AuthRequest extends Request {
    userId?: string;
    userRole?: UserRole; // Assuming authMiddleware sets the user's role
}

export const deletePostController = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const postId = req.params.postId;
        const currentAuthUserId = req.userId; 
        const currentUserRole = req.userRole; 

        if (!currentAuthUserId || !currentUserRole) {
            // Should be caught by authMiddleware, but check defensively
            return res.status(403).json({ message: 'Authentication required.' });
        }

        await deletePost(
            postId, 
            currentAuthUserId,
            currentUserRole
        );

        // Success response for DELETE is typically 204 No Content
        return res.status(204).send();

    } catch (error: any) {
        // Delegate error handling to the Express error handler
        next(error);
    }
};



// Custom interface for authenticated request (ensuring userRole is passed)
interface AuthRequest extends Request {
    userId?: string;
    userRole?: UserRole; // Assuming authMiddleware sets the user's role
}

// --- Like Post Controller ---

export const likePostController = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const postId = req.params.postId;
        const currentAuthUserId = req.userId; 
        const currentUserRole = req.userRole; 

        if (!currentAuthUserId || !currentUserRole) {
            return res.status(403).json({ message: 'Authentication required.' });
        }

        const result = await likePost(postId, currentAuthUserId, currentUserRole);

        // Realtime: This event would typically be emitted here or in a wrapper after the controller.
        // Assuming your setup handles socket events after the response is sent.
        // io.emit(`postUpdate:${postId}`, result); 

        return res.status(200).json(result);

    } catch (error: any) {
        next(error);
    }
};

// --- Dislike Post Controller ---

export const dislikePostController = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const postId = req.params.postId;
        const currentAuthUserId = req.userId; 
        const currentUserRole = req.userRole; 

        if (!currentAuthUserId || !currentUserRole) {
            return res.status(403).json({ message: 'Authentication required.' });
        }

        const result = await dislikePost(postId, currentAuthUserId, currentUserRole);

        // Realtime: Emit event on success
        // io.emit(`postUpdate:${postId}`, result); 

        return res.status(200).json(result);

    } catch (error: any) {
        next(error);
    }
};
