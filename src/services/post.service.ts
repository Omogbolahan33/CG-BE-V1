import prisma from '../utils/prisma';
import { Prisma, UserRole } from '@prisma/client';
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




/**
 * Service: Update Post
 * @description Updates an existing post with complex business logic.
 */
export const updatePost = async (
    postId: string, 
    postData: any, 
    currentAuthUserId: string,
    currentUser: AuthUser // Full user object needed for bankAccount check
): Promise<Post> => {
    
    // 1. Fetch Current Post and Authorization Check
    const currentPost = await prisma.post.findUnique({ 
        where: { id: postId },
    });

    if (!currentPost) {
        throw new NotFoundError('Post not found.');
    }

    // @authorization: User must be the author
    if (currentPost.authorId !== currentAuthUserId) {
        throw new ForbiddenError('You do not have permission to edit this post.');
    }

    // 2. Initial Data Preparation and Sanitization
    const updateData: Partial<Prisma.PostUpdateInput> = {};
    const originalIsAdvert = currentPost.isAdvert;
    
    // **Security:** The incoming content MUST be sanitized.
    if (postData.content) {
        updateData.content = sanitizePostContent(postData.content as string); 
    }

    // **Core Logic 2:** The `isAdvert` field from the request body MUST be ignored.
    const { isAdvert, categoryId, ...safePostData } = postData as any;
    Object.assign(updateData, safePostData); 

    // 3. Category Update Logic
    const newCategoryId = categoryId as string | undefined;

    if (newCategoryId && newCategoryId !== currentPost.categoryId) {
        
        // 3a. Fetch the new Category record.
        const newCategory = await prisma.category.findUnique({ 
            where: { id: newCategoryId },
            select: { type: true }
        });

        if (!newCategory) {
            throw new BadRequestError('Invalid category ID.');
        }

        // 3b. Determine the new `isAdvert` value
        const newIsAdvert = newCategory.type === 'advert';
        
        // 3c. Update the post's `isAdvert` field.
        updateData.isAdvert = newIsAdvert;
        updateData.category = { connect: { id: newCategoryId }};

        // --- Conditional Logic based on Type Change ---

        if (newIsAdvert && !originalIsAdvert) {
            // 3d. Post changing FROM discussion TO advert: Check bank account
            if (!currentUser.hasBankAccount) {
                // @errorHandling: 400 Bad Request
                throw new BadRequestError('Bank account must be configured to convert a discussion to an advertisement.'); 
            }
        } else if (!newIsAdvert && originalIsAdvert) {
            // 3e. Post changing FROM advert TO discussion: Nullify advert-specific fields
            updateData.price = null;
            updateData.condition = null;
            updateData.brand = null;
            updateData.deliveryOptions = Prisma.JsonNull;
            updateData.quantity = null;
        }
    }
    
    // 4. Final Database Update
    // Core Logic 1: Set the `editedTimestamp`
    updateData.editedTimestamp = new Date(); 

    const updatedPost = await prisma.post.update({ 
        where: { id: postId },
        data: updateData,
    }) as unknown as Post; 

    return updatedPost;
};



/**
 * Service: Delete Post
 * @description Deletes an existing post.
 * @authorization User must be the author or an Admin/Super Admin.
 * @transactional Ensures the post is deleted and, via cascading, all related records.
 */
export const deletePost = async (
    postId: string, 
    currentAuthUserId: string,
    currentUserRole: UserRole // Assuming the user's role is passed from the controller
): Promise<{ success: boolean }> => {
    
    // 1. Fetch Post and Authorization Check
    const postToDelete = await prisma.post.findUnique({ 
        where: { id: postId },
        select: { authorId: true } // Only need authorId for the check
    });

    if (!postToDelete) {
        throw new NotFoundError('Post not found.');
    }

    // @authorization: User must be the author OR an Admin/Super Admin.
    const isAuthor = postToDelete.authorId === currentAuthUserId;
    const isAdmin = currentUserRole === UserRole.Admin || currentUserRole === UserRole.SuperAdmin;

    if (!isAuthor && !isAdmin) {
        throw new ForbiddenError('You do not have permission to delete this post.');
    }

    // 2. Core Logic: Delete the Post (Cascading Deletion)
    // We rely on the database schema's onDelete: Cascade to handle:
    // - Comments
    // - Notifications (or any other related records)
    
    // Use a transaction for safety, though a single delete operation is often enough
    // if cascading is configured correctly. We use the single delete for simplicity
    // and efficiency, assuming CASCADE is set.

    await prisma.post.delete({ 
        where: { id: postId },
    });
    
    // Note: No need for explicit 'db.comment.deleteMany' if CASCADE is on.

    return { success: true };
};




interface LikeDislikeResponse {
    likedBy: string[];
    dislikedBy: string[];
}





/**
 * Executes the atomic update logic for liking or disliking a post.
 * @param postId The ID of the post to update.
 * @param userId The ID of the user performing the action.
 * @param isLikeAction True for Like, False for Dislike.
 * @returns The updated likedBy and dislikedBy arrays.
 */
const toggleVote = async (
    postId: string, 
    userId: string, 
    isLikeAction: boolean
): Promise<LikeDislikeResponse> => {
    
    // We use a transaction to ensure atomicity for the read-modify-write cycle.
    const result = await prisma.$transaction(async (tx) => {
        // 1. Fetch the current state of the post
        const post = await tx.post.findUnique({
            where: { id: postId },
            select: { 
                likedBy: { select: { id: true } }, 
                dislikedBy: { select: { id: true } },
                authorId: true 
            }
        });

        if (!post) {
            throw new NotFoundError('Post not found.');
        }

       // Convert relations to simple ID arrays for easier logic checks
        const likedByIds = post.likedBy.map(u => u.id);
        const dislikedByIds = post.dislikedBy.map(u => u.id);
        
        const currentlyLiked = likedByIds.includes(userId);
        const currentlyDisliked = dislikedByIds.includes(userId);
        
        // This object holds all the relational changes
        let updateData: Prisma.PostUpdateInput = {
            lastActivityTimestamp: new Date(),
        };
        let notificationNeeded = false;

        const userConnect = { id: userId }; // Standard object for connect/disconnect operations

        if (isLikeAction) {
            // Logic for LIKE Post
            
            // 1. If user ID is in dislikedBy, remove it (DISCONNECT).
            if (currentlyDisliked) {
                updateData.dislikedBy = { disconnect: userConnect };
            }

            // 2. If user ID is in likedBy, remove it (UNLIKE - DISCONNECT). Else, add it (LIKE - CONNECT).
            if (currentlyLiked) {
                updateData.likedBy = { disconnect: userConnect };
            } else {
                updateData.likedBy = { connect: userConnect };
                notificationNeeded = (post.authorId !== userId); 
            }

        } else {
            // Logic for DISLIKE Post

            // 1. If user ID is in likedBy, remove it (DISCONNECT).
            if (currentlyLiked) {
                updateData.likedBy = { disconnect: userConnect };
            }

            // 2. If user ID is in dislikedBy, remove it (UNDISLIKE - DISCONNECT). Else, add it (DISLIKE - CONNECT).
            if (currentlyDisliked) {
                updateData.dislikedBy = { disconnect: userConnect };
            } else {
                updateData.dislikedBy = { connect: userConnect };
            }
        }
        
        // 3. Perform the update and retrieve the new lists of IDs
        const updatedPost = await tx.post.update({
            where: { id: postId },
            data: updateData,
            select: { 
                likedBy: { select: { id: true } }, 
                dislikedBy: { select: { id: true } }, 
                authorId: true 
            }
        });
        
        return { 
            likedBy: updatedPost.likedBy.map(u => u.id), 
            dislikedBy: updatedPost.dislikedBy.map(u => u.id), 
            authorId: updatedPost.authorId,
            notificationNeeded
        };
    });
    
    // Side Effects (Outside the transaction)
    if (result.notificationNeeded) {
        // Side Effects: Queue 'like' notification
        await queueJob('SEND_NOTIFICATION', {
            type: 'POST_LIKED',
            recipientId: result.authorId,
            details: { postId, likerId: userId }
        });
    }

    // Return the final string arrays of IDs
    return { likedBy: result.likedBy, dislikedBy: result.dislikedBy };
};

// --- Main Service Functions ---

/**
 * Toggles a like on a post.
 */
export const likePost = async (
    postId: string, 
    currentAuthUserId: string,
    currentUserRole: AuthUser['role'] // Assuming role is available on AuthUser
): Promise<LikeDislikeResponse> => {
    
    // Pre-conditions: Check Backoffice setting `enableLikes`
    const settings = await getBackofficeSettings();
    const canLike = currentUserRole !== 'Member' || settings.enableLikes; 
    
    if (!canLike) {
        throw new ForbiddenError('Liking posts is currently disabled.');
    }

    return toggleVote(postId, currentAuthUserId, true); // true = isLikeAction
};

/**
 * Toggles a dislike on a post.
 */
export const dislikePost = async (
    postId: string, 
    currentAuthUserId: string,
    currentUserRole: AuthUser['role']
): Promise<LikeDislikeResponse> => {
    
    // Pre-conditions: Check Backoffice setting `enableLikes`
    const settings = await getBackofficeSettings();
    const canDislike = currentUserRole !== 'Member' || settings.enableLikes; 
    
    if (!canDislike) {
        throw new ForbiddenError('Disliking posts is currently disabled.');
    }

    return toggleVote(postId, currentAuthUserId, false); // false = isDislikeAction
};







/**
 * Service: Follow/Unfollow Post
 * @description Toggles following a specific post to receive notifications on new comments.
 * @coreLogic Atomically adds or removes the postId from the current user's followedPostIds array.
 */
interface FollowResponse {
    followedPostIds: string[];
}


export const followPost = async (
    postId: string, 
    currentAuthUserId: string
): Promise<FollowResponse> => {
    
    // Define the Post object for connect/disconnect operations
    const postConnect = { id: postId };

    // 1. Fetch the user's current followedPostIds to determine action
    const user = await prisma.user.findUnique({
        where: { id: currentAuthUserId },
        // Select the IDs from the 'followedPosts' relation
        select: { 
            followedPosts: { 
                select: { id: true } 
            } 
        }
    });

    if (!user) {
        throw new NotFoundError('User not found.');
    }

    // Determine current state
    const followedPostIds = user.followedPosts.map(p => p.id);
    const currentlyFollowing = followedPostIds.includes(postId);

    let updateData: Prisma.UserUpdateInput;

    if (currentlyFollowing) {
        // Unfollow: Atomically remove the Post from the relation
        updateData = {
            followedPosts: {
                disconnect: postConnect
            }
        };
    } else {
        // Follow: Atomically add the Post to the relation
        updateData = {
            followedPosts: {
                connect: postConnect
            }
        };
    }
    
    // 2. Perform the atomic update on the User model
    const updatedUser = await prisma.user.update({
        where: { id: currentAuthUserId },
        data: updateData,
        // Select the IDs from the updated relation to return
        select: { 
            followedPosts: { 
                select: { id: true } 
            } 
        }
    });

    // 3. Side Effect (Realtime) - A notification job is NOT required here,
    //    as the notification for 'followed_post_comment' is triggered when a comment is created.
    
    // 4. Return the array of IDs
    const updatedFollowedPostIds = updatedUser.followedPosts.map(p => p.id);
    
    return { followedPostIds: updatedFollowedPostIds };
};






/**
 * Service: Flag Post
 * @description Adds a flag to a post for moderator review.
 * @coreLogic Connects the current user to the post's 'flaggedBy' relation.
 */
export const flagPost = async (
    postId: string, 
    currentAuthUserId: string
): Promise<{ success: boolean }> => {
    
    // 1. Check if the post exists
    const postExists = await prisma.post.findUnique({
        where: { id: postId },
        select: { id: true }
    });

    if (!postExists) {
        throw new NotFoundError('Post not found.');
    }

    // Define the User object for the connect operation
    const userConnect = { id: currentAuthUserId };
    
    // 2. Core Logic: Atomically add the user's ID to the post's flaggedBy relation
    // If the relationship already exists (user has flagged before), Prisma ignores the 'connect' command.
    await prisma.post.update({
        where: { id: postId },
        data: {
            flaggedBy: {
                connect: userConnect // Adds the user ID to the flaggedBy relation
            },
            // Update last activity timestamp on flag (optional, but useful)
            lastActivityTimestamp: new Date(), 
        },
    });

    return { success: true };
};





/**
 * Service: Toggle Post Sold Out Status
 * @description Manually toggles the 'isSoldOut' status of an advertisement.
 */
export const toggleSoldOutStatus = async (
    postId: string, 
    currentAuthUserId: string
): Promise<Post> => {
    
    // 1. Find the post and select fields needed for checks
    const currentPost = await prisma.post.findUnique({ 
        where: { id: postId },
        select: { 
            id: true, 
            authorId: true, 
            isAdvert: true, 
            isSoldOut: true 
        }
    });

    if (!currentPost) {
        throw new NotFoundError('Post not found.');
    }

    // 2. Authorization and Pre-condition Check
    
    // Authorization: User must be the author
    if (currentPost.authorId !== currentAuthUserId) {
        throw new ForbiddenError('You do not have permission to modify this post.');
    }
    
    // Pre-condition: Post must be an advert
    if (currentPost.isAdvert !== true) {
        // We use ForbiddenError here as specified, though BadRequestError would also be acceptable
        throw new ForbiddenError('Only advertisements can have their sold out status toggled.');
    }

    // 3. Core Logic: Toggle the boolean value of the isSoldOut field.
    const newIsSoldOutStatus = !currentPost.isSoldOut;

    // 4. Save and return the updated post object.
    const updatedPost = await prisma.post.update({ 
        where: { id: postId },
        data: {
            isSoldOut: newIsSoldOutStatus
        },
    }) as unknown as Post; // Cast to your simple Post type

    return updatedPost;
};
