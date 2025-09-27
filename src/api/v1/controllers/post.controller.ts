import { Request, Response, NextFunction } from 'express';
import { GetPostsFilters, AuthUser, CreatePostPayload } from '../../../types';
import { getPosts, getPostDetails, createPost  } from '../../../services/post.service'; 
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
