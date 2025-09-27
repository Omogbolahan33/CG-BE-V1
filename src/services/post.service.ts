// src/services/post.service.ts

import prisma from '../utils/prisma';
import { Prisma } from '@prisma/client'; 
import { calculateTrendingScore } from '../utils/score.util';
import { sanitizePostContent } from '../utils/sanitize-html'; // <-- Correct, singular import of wrapper
import { getBackofficeSettings } from '../utils/settings.util'; 
import { queueJob } from '../utils/job-queue.util'; 
import { nestComments, NestedComment } from '../utils/comment-nesting.util';
import { BadRequestError } from '../errors/BadRequestError'; // <-- Required for input validation
import { NotFoundError } from '../errors/NotFoundError';
import { ForbiddenError } from '../errors/ForbiddenError'; 
import { Post, GetPostsFilters, Comment, AuthUser, CreatePostPayload } from '../types'; 


/**
 * Defines the minimum required fields from the Post model for fetching.
 * Includes fields necessary for sorting (likesCount, pinnedAt, price) and presentation.
 */
const POST_SELECT_FIELDS = {
    id: true,
    title: true, 
    timestamp: true, 
    lastActivityTimestamp: true, 
    isAdvert: true, 
    isSoldOut: true, // Required
    isCommentingRestricted: true, // Required
    categoryId: true,
    editedTimestamp: true,
    quantity: true,
    brand: true,
    condition: true,
    deliveryOptions: true,
    media: true,
    content: true,
    likesCount: true,
    commentsCount: true,
    pinnedAt: true,
    price: true,
    authorId: true,
    author: {
        select: { id: true, username: true } // Example of including related data
    }
};

/**
 * API: Get Posts
 * @description Fetches a list of posts with filtering, sorting, and pagination.
 */
export const getPosts = async (filters: GetPostsFilters): Promise<{ posts: Post[], total: number }> => {
    
    let { 
        viewMode, 
        sortMode = 'new', 
        advertSort = 'newest', 
        limit = 20, 
        offset = 0, 
        minPrice 
    } = filters;

    // --- 1. Error Handling & Input Validation ---
    
    const MAX_LIMIT = 100;

    // Validation 1: Limit and Offset
    if (limit <= 0 || limit > MAX_LIMIT) {
        throw new BadRequestError(`'limit' must be between 1 and ${MAX_LIMIT}.`, 400);
    }
    if (offset < 0) {
        throw new BadRequestError("'offset' cannot be negative.", 400);
    }
    
    // Validation 2: Price
    if (minPrice !== undefined && minPrice < 0) {
        throw new BadRequestError("'minPrice' cannot be negative.", 400);
    }


    // --- 2. Base Query Definition ---
    const where: Prisma.PostWhereInput = {
        isAdvert: viewMode === 'adverts',
        
        ...(viewMode === 'adverts' && minPrice !== undefined && {
            price: { gte: minPrice }
        })
    };

    let orderBy: Prisma.PostOrderByWithRelationInput = {};
    let fetchedPosts: Post[] = []; 
    let total: number = 0; 
    let shouldQueryFromDB = true; // Flag for standard DB query path

    // --- 3. Sorting Logic (Custom Logic vs. DB Logic) ---

    if (viewMode === 'adverts') {
        // Standard DB Sorting for Adverts
        switch (advertSort) {
            case 'price_asc':
                orderBy = { price: 'asc' };
                break;
            case 'price_desc':
                orderBy = { price: 'desc' };
                break;
            case 'newest':
            default:
                orderBy = { timestamp: 'desc' };
                break;
        }
    } else { // viewMode === 'discussions'
        switch (sortMode) {
            case 'new':
                orderBy = { timestamp: 'desc' }; 
                break;
                
            case 'top':
            case 'trending':
            {
                // In-Memory Sorting Path
                shouldQueryFromDB = false; 
                
                // Fetch a reasonable set for accurate ranking before pagination
                const allPosts = await prisma.post.findMany({
                    where,
                    select: POST_SELECT_FIELDS,
                    take: 500, 
                }) as Post[]; 

                if (sortMode === 'top') {
                    // @businessLogic: 'top' sorting (Pinned + Engagement Score)
                    fetchedPosts = allPosts
                        .map(post => ({ ...post, engagementScore: post.likesCount + post.commentsCount }))
                        .sort((a, b) => {
                            const now = new Date();
                            const twentyFourHoursAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

                            const aPinnedRecent = a.pinnedAt && a.pinnedAt > twentyFourHoursAgo;
                            const bPinnedRecent = b.pinnedAt && b.pinnedAt > twentyFourHoursAgo;

                            if (aPinnedRecent && !bPinnedRecent) return -1;
                            if (!aPinnedRecent && bPinnedRecent) return 1;
                            
                            // Sort by Engagement Score
                            return (b as any).engagementScore - (a as any).engagementScore;
                        });
                } else { // sortMode === 'trending'
                    // @businessLogic: 'trending' sorting (Complex Score)
                    fetchedPosts = allPosts
                        .map(post => ({ 
                            ...post, 
                            trendingScore: calculateTrendingScore(post.likesCount, post.commentsCount, post.timestamp) 
                        }))
                        .sort((a, b) => (b as any).trendingScore - (a as any).trendingScore);
                }
                
                // CORRECTION: Get the total count correctly, independent of the fetched set size
                total = await prisma.post.count({ where });
                
                // Apply final pagination (slice) after sorting
                fetchedPosts = fetchedPosts.slice(offset, offset + limit);
                break;
            }
                
            default:
                orderBy = { timestamp: 'desc' };
                break;
        }
    }

    // --- 4. Execute Query (Standard DB path) ---
   if (shouldQueryFromDB) {
        // FIX 2: Use the functional overload for $transaction to simplify type handling.
        const [postsData, countData] = await prisma.$transaction(async (tx) => {
            const posts = await tx.post.findMany({
                where,
                orderBy,
                take: limit,
                skip: offset,
                select: POST_SELECT_FIELDS,
            });
            const count = await tx.post.count({ where });
            return [posts, count];
        });
        
        // Assign results after casting
        fetchedPosts = postsData as unknown as Post[]; 
        total = countData;
    }


    // --- 5. Security & Cleanup ---
    // CORRECTION: Use the dedicated sanitizePostContent wrapper function
    const sanitizedPosts = fetchedPosts.map(post => ({
        ...post,
        content: sanitizePostContent(post.content),
    })) as Post[]; 
    
    return { posts: sanitizedPosts, total };
};



/**
 * API: Get Post Details
 * @description Fetches a single post with its full comment hierarchy.
 */
export const getPostDetails = async (postId: string): Promise<Post> => {
    
    // 1. Fetch the Post and all its related comments
    const post = await prisma.post.findUnique({
        where: { id: postId },
        // Select all required post details and include all comments
        select: {
            // Include all fields required by your local Post type
            id: true,
            title: true, 
            content: true,
            timestamp: true, 
            lastActivityTimestamp: true, 
            isAdvert: true, 
            isSoldOut: true, 
            isCommentingRestricted: true, 
            price: true,
            pinnedAt: true,
            authorId: true,
            categoryId: true,
            
            // Include related data
            author: { select: { id: true, username: true } },
            category: { select: { id: true, name: true } },
            
            // Include all comments (flat list)
            comments: {
                orderBy: { timestamp: 'asc' }, // Order by creation time
                select: {
                    id: true,
                    content: true,
                    timestamp: true,
                    parentId: true, // Crucial for nesting
                    // Include comment author details
                    author: { select: { id: true, username: true } },
                    // Include necessary counts (likes, etc.)
                    // ...
                }
            },
            // Note: likesCount/commentsCount are usually fetched separately or via middleware 
        }
    }) as (Post & { comments: Comment[] }) | null;


    // 2. Error Handling
    if (!post) {
        // @errorHandling: 404 Not Found
        throw new NotFoundError(`Post with ID ${postId} not found.`);
    }

    // 3. Security & Sanitization
    // Sanitize the main post content
    const sanitizedPostContent = sanitizePostContent(post.content);

    // Sanitize all comment content
    const sanitizedComments = post.comments.map(comment => ({
        ...comment,
        content: sanitizePostContent(comment.content)
    })) as Comment[];
    
    
    // 4. Business Logic: Nest Comments
    const nestedComments = nestComments(sanitizedComments);
    
    
    // 5. Final Structure Assembly
    // Note: The final returned Post object should match the Post schema.
    // Assuming your 'Post' type requires comments to be nested:
    const finalPost: Post = {
        ...post,
        content: sanitizedPostContent,
        // The 'comments' field on the final Post object is assumed to be the nested structure
        comments: nestedComments as any, // Cast to any to handle nested type complexity
    } as any; 

    // Remove the computed counts for this specific detail view if they don't belong here
    delete (finalPost as any).likesCount;
    delete (finalPost as any).commentsCount;

    return finalPost;
};



/**
 * API: Create Post
 * @description Creates a new post with zero redundant DB calls for user details.
 */
export const createPost = async (
    postData: CreatePostPayload, 
    authUser: AuthUser // Contains ID, role, isBanned, and hasBankAccount status
): Promise<Post> => {
    
    const { categoryId, title, content, price, ...advertData } = postData;
    const authorId = authUser.id; 

    // --- 1. Fetch Category and Global Settings ---

    // DB Call 1: Fetch category to determine isAdvert status
    const category = await prisma.category.findUnique({
        where: { id: categoryId },
        select: { id: true, type: true } 
    });

    if (!category) {
        throw new BadRequestError(`Category ID ${categoryId} is invalid.`, 400);
    }
    
    // DB Call 2 (or Cache Hit): Fetch global settings
    const settings = await getBackofficeSettings(); 
    const isAdvert = category.type === 'advert';
    
    // --- 2. Security and Pre-conditions (Using AuthUser Data) ---
    
    // Pre-condition 1: User Ban Check
    if (authUser.isBanned) {
        // @errorHandling: 403 Forbidden
        throw new ForbiddenError("You are banned and cannot create posts.", 403);
    }
    
    // Pre-condition 2: General Post Creation Feature Flag
    if (!settings.enablePostCreation) {
        // @errorHandling: 403 Forbidden
        throw new ForbiddenError("Post creation is currently disabled.", 403);
    }
    
    // Pre-condition 3: Advertisement-Specific Checks
    if (isAdvert) {
        if (!settings.enableAdvertisements) {
            // @errorHandling: 403 Forbidden
            throw new ForbiddenError("Advertisement feature is disabled.", 403);
        }
        // User MUST have a bankAccount configured (Uses authUser.hasBankAccount, NO DB CALL)
        if (!authUser.hasBankAccount) {
            // @errorHandling: 400 Bad Request
            throw new BadRequestError("Bank account must be configured to create an advertisement.", 400);
        }
        // Advertisements must have a valid price
        if (price === undefined || price === null || (price as number) <= 0) {
            // @errorHandling: 400 Bad Request
            throw new BadRequestError("Advertisements must include a positive price.", 400);
        }
    }
    
    // --- 3. Content Security and Core Creation ---
    
    // @security: Sanitize the incoming content before DB storage
    const sanitizedContent = sanitizePostContent(content); 

    // DB Call 3: Create Post
    const createdPost = await prisma.post.create({
        data: {
            title,
            content: sanitizedContent,
            isAdvert: isAdvert,
            price: price || null,
            
            author: { connect: { id: authorId } },
            category: { connect: { id: categoryId } },
            ...advertData, 
        },
        // Select all required fields for the response
        // Note: You must ensure this select matches your Post interface
        select: {
            id: true, title: true, content: true, timestamp: true, lastActivityTimestamp: true, 
            isAdvert: true, price: true, pinnedAt: true, isSoldOut: true, isCommentingRestricted: true,
            quantity: true, brand: true, condition: true, deliveryOptions: true, media: true,
            authorId: true, categoryId: true, editedTimestamp: true
        }
    }) as Post; 


    // --- 4. Side Effects (Background Jobs) ---
    
    // Side Effect 1: Activity Log (Synchronous DB write)
    await prisma.activityLog.create({
        data: {
            userId: authorId,
            action: 'POST_CREATED',
            // 🔥 FIX: Stringify the object if ActivityLog.details is a String
            // If your schema uses 'Json', remove JSON.stringify().
            details: JSON.stringify({ postId: createdPost.id, title: createdPost.title }) 
        }
            //Recommendation: If you want to query structured data later 
            //(e.g., "Find all activity logs related to post X"), 
            //you must update your Prisma model to use details Json? for this field.
    });

    // Side Effect 2: Notification Fan-Out (Asynchronous BullMQ Job)
    // @scalability: Non-blocking call.
    queueJob('NOTIFY_FOLLOWERS_OF_NEW_POST', {
        authorId: authorId,
        postId: createdPost.id,
        isAdvert: isAdvert
    });

    return createdPost;
};
