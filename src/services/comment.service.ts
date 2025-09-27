import prisma from '../utils/prisma';
import { Post, Comment, AuthUser } from '../types';
import { ForbiddenError } from '../errors/ForbiddenError';
import { NotFoundError } from '../errors/NotFoundError';
// ... import all necessary utilities:
import { sanitizePostContent as sanitizeCommentContent } from '../utils/sanitize-html'; 
import { getBackofficeSettings } from '../utils/settings.util'; 
import { parseMentions } from '../utils/mention.util'; 
import { queueJob } from '../utils/job-queue.util'; 
import { UserRole, Prisma } from '@prisma/client';

/**
 * API: Add Comment
 * @description Adds a comment or reply to a post with complex notification logic.
 */
export const addComment = async (
    postId: string, 
    commentData: { content: string; media?: any[] }, 
    parentId: string | null,
    currentAuthUserId: string,
    currentUserRole: UserRole
): Promise<Comment> => {

    const userIsAdmin = currentUserRole === UserRole.Admin || currentUserRole === UserRole.SuperAdmin;

    // 1. Fetch Post, Parent Comment (if applicable), and Settings
    // ... (implementation logic from previous response remains here)
    const [post, parentComment, settings] = await Promise.all([
        prisma.post.findUnique({
            where: { id: postId },
            select: { 
                id: true, 
                authorId: true, 
                isCommentingRestricted: true,
                followedBy: { select: { id: true } }
            }
        }),
        parentId ? prisma.comment.findUnique({ where: { id: parentId }, select: { authorId: true } }) : Promise.resolve(null),
        getBackofficeSettings()
    ]);

    if (!post) {
        throw new NotFoundError('Post not found.');
    }

    // 2. Pre-conditions Check
    const isCommentingAllowed = settings.enableCommenting || userIsAdmin;
    const isPostRestricted = post.isCommentingRestricted && !userIsAdmin;

    if (!isCommentingAllowed) {
        throw new ForbiddenError('Commenting is globally disabled.');
    }
    if (isPostRestricted) {
        throw new ForbiddenError('Commenting is restricted on this post.');
    }

    // 3. Core Logic: Transactional Creation and Update
    const sanitizedContent = sanitizeCommentContent(commentData.content);
    const mentionedUsernames = parseMentions(sanitizedContent);

    const newComment = await prisma.$transaction(async (tx) => {
        
        // 3.1. Create the Comment record
        const createdComment = await tx.comment.create({
            data: {
                content: sanitizedContent,
                media: commentData.media as Prisma.JsonArray,
                post: { connect: { id: postId } }, 
                ...(parentId && { parent: { connect: { id: parentId } } }),
                author: { connect: { id: currentAuthUserId } },
            } as Prisma.CommentCreateInput
        }) as unknown as Comment; 

        // 3.2. Atomically update the parent post's lastActivityTimestamp
        await tx.post.update({
            where: { id: postId },
            data: {
                lastActivityTimestamp: new Date(),
            }
        });

        return createdComment;
    });

    // 4. Side Effects (Asynchronous Job Queuing)
    
    // ... (Notification and Activity Log logic remains here)
    const notifiedUserIds = new Set<string>([currentAuthUserId]);
    const notificationsToQueue: any[] = [];
    let parentCommentAuthorId: string | null = parentComment?.authorId || null;

    queueJob('CREATE_ACTIVITY_LOG', { /* ... */ });
    
    // 4.2. Mentions
    // ... logic to find mentioned users and queue notifications ...
    if (mentionedUsernames.length > 0) {
        const mentionedUsers = await prisma.user.findMany({
            where: { username: { in: mentionedUsernames } },
            select: { id: true }
        });

        mentionedUsers.forEach(user => {
            if (!notifiedUserIds.has(user.id)) {
                notificationsToQueue.push({
                    type: 'MENTION', recipientId: user.id,
                    details: { postId, commentId: newComment.id, commenterId: currentAuthUserId }
                });
                notifiedUserIds.add(user.id);
            }
        });
    }

    // 4.3. Replies (Parent Comment Author)
    if (parentId && parentCommentAuthorId && !notifiedUserIds.has(parentCommentAuthorId)) {
        notificationsToQueue.push({
            type: 'COMMENT_REPLY', recipientId: parentCommentAuthorId,
            details: { postId, commentId: newComment.id, commenterId: currentAuthUserId }
        });
        notifiedUserIds.add(parentCommentAuthorId);
    }
    
    // 4.4. Post Author
    if (post.authorId !== currentAuthUserId && !notifiedUserIds.has(post.authorId)) {
        notificationsToQueue.push({
            type: 'NEW_COMMENT_ON_POST', recipientId: post.authorId,
            details: { postId, commentId: newComment.id, commenterId: currentAuthUserId }
        });
        notifiedUserIds.add(post.authorId);
    }

    // 4.5. Post Followers
    post.followedBy.forEach(user => {
        if (!notifiedUserIds.has(user.id)) {
            notificationsToQueue.push({
                type: 'FOLLOWED_POST_COMMENT', recipientId: user.id,
                details: { postId, commentId: newComment.id, commenterId: currentAuthUserId }
            });
            notifiedUserIds.add(user.id);
        }
    });

    notificationsToQueue.forEach(job => queueJob('SEND_NOTIFICATION', job));

    return newComment;
};





/**
 * API: Edit Comment
 * @description Edits an existing comment.
 * @authorization User must be the author of the comment.
 */
export const editComment = async (
    postId: string, 
    commentId: string, 
    newContent: string,
    currentAuthUserId: string
): Promise<Comment> => {
    
    // 1. Fetch the comment and check existence/authorization
    const commentToEdit = await prisma.comment.findUnique({ 
        where: { id: commentId },
        select: { 
            id: true, 
            authorId: true, 
            postId: true, 
        }
    });

    if (!commentToEdit) {
        throw new NotFoundError('Comment not found.');
    }

    // Authorization: User must be the author
    if (commentToEdit.authorId !== currentAuthUserId) {
        throw new ForbiddenError('You do not have permission to edit this comment.');
    }

    // Pre-condition: Comment must belong to the correct post (for robust path validation)
    if (commentToEdit.postId !== postId) {
        // This indicates an incorrect URL usage, though 404/403 are both acceptable here.
        throw new NotFoundError('Comment does not belong to the specified post.');
    }

    // 2. Security: Sanitize new content
    const sanitizedContent = sanitizeCommentContent(newContent);

    // 3. Core Logic: Update content and set editedAt timestamp
    const updatedComment = await prisma.comment.update({ 
        where: { id: commentId },
        data: {
            content: sanitizedContent,
            editedTimestamp: new Date(), // Set the edited timestamp
        },
    }) as unknown as Comment; // Cast to your simple Comment type

    return updatedComment;
};



/**
 * API: Delete Comment
 * @description Deletes a comment.
 * @authorization User must be the author or an Admin/Super Admin.
 */
export const deleteComment = async (
    postId: string, 
    commentId: string,
    currentAuthUserId: string,
    currentUserRole: UserRole
): Promise<{ success: boolean }> => {
    
    // 1. Fetch the comment and check existence
    const commentToDelete = await prisma.comment.findUnique({ 
        where: { id: commentId },
        select: { 
            id: true, 
            authorId: true, 
            postId: true, 
        }
    });

    if (!commentToDelete) {
        throw new NotFoundError('Comment not found.');
    }

    // Authorization: User must be the author OR an Admin/Super Admin.
    const isAuthor = commentToDelete.authorId === currentAuthUserId;
    const isAdmin = currentUserRole === UserRole.Admin || currentUserRole === UserRole.SuperAdmin;

    if (!isAuthor && !isAdmin) {
        throw new ForbiddenError('You do not have permission to delete this comment.');
    }
    
    // Pre-condition: Comment must belong to the correct post (for path validation)
    if (commentToDelete.postId !== postId) {
        throw new NotFoundError('Comment does not belong to the specified post.');
    }

    // 2. Core Logic: Delete the Comment
    // We rely on the database schema's onDelete: Cascade to handle:
    // - Nested replies (children comments)
    // - Any related notifications or activity logs
    
    await prisma.comment.delete({ 
        where: { id: commentId },
    });
    
    return { success: true };
};





/**
 * API: Like/Dislike Comment
 * @description Deletes a comment.
 * @authorization User must be the author or an Admin/Super Admin.
 */



interface LikeDislikeResponse {
    likedBy: string[];
    dislikedBy: string[];
}

/**
 * Executes the atomic update logic for liking or disliking a comment.
 */
const toggleCommentVote = async (
    commentId: string, 
    userId: string, 
    isLikeAction: boolean
): Promise<LikeDislikeResponse> => {
    
    // We use a transaction to ensure atomicity for the read-modify-write cycle.
    const result = await prisma.$transaction(async (tx) => {
        // 1. Fetch the current state of the comment
        const comment = await tx.comment.findUnique({
            where: { id: commentId },
            select: { 
                likedBy: { select: { id: true } }, 
                dislikedBy: { select: { id: true } }, 
                authorId: true,
                postId: true // Need postId for the realtime event
            }
        });

        if (!comment) {
            throw new NotFoundError('Comment not found.');
        }

        // Convert relations to simple ID arrays for logic checks
        const likedByIds = comment.likedBy.map(u => u.id);
        const dislikedByIds = comment.dislikedBy.map(u => u.id);
        
        const currentlyLiked = likedByIds.includes(userId);
        const currentlyDisliked = dislikedByIds.includes(userId);
        
        let updateData: Prisma.CommentUpdateInput = {};
        let notificationNeeded = false;

        const userConnect = { id: userId }; 

        if (isLikeAction) {
            // Logic for LIKE Comment
            
            // 1. If user ID is in dislikedBy, remove it (DISCONNECT).
            if (currentlyDisliked) {
                updateData.dislikedBy = { disconnect: userConnect };
            }

            // 2. If user ID is in likedBy, remove it (UNLIKE - DISCONNECT). Else, add it (LIKE - CONNECT).
            if (currentlyLiked) {
                updateData.likedBy = { disconnect: userConnect };
            } else {
                updateData.likedBy = { connect: userConnect };
                // Side Effect check: If a LIKE was ADDED and it's not a self-like
                notificationNeeded = (comment.authorId !== userId); 
            }

        } else {
            // Logic for DISLIKE Comment

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
        const updatedComment = await tx.comment.update({
            where: { id: commentId },
            data: updateData,
            select: { 
                likedBy: { select: { id: true } }, 
                dislikedBy: { select: { id: true } }, 
                authorId: true,
                postId: true
            }
        });
        
        return { 
            likedBy: updatedComment.likedBy.map(u => u.id), 
            dislikedBy: updatedComment.dislikedBy.map(u => u.id), 
            authorId: updatedComment.authorId,
            postId: updatedComment.postId,
            notificationNeeded
        };
    });
    
    // Side Effects (Outside the transaction)
    if (result.notificationNeeded) {
        // Side Effects: Queue 'comment_like' notification
        await queueJob('SEND_NOTIFICATION', {
            type: 'COMMENT_LIKED', // Assuming the type is COMMENT_LIKED or similar
            recipientId: result.authorId,
            details: { 
                postId: result.postId, 
                commentId: commentId, 
                likerId: userId 
            }
        });
    }

    return { likedBy: result.likedBy, dislikedBy: result.dislikedBy };
};

// --- Main Service Functions ---

/**
 * Toggles a like on a comment.
 */
export const likeComment = async (
    postId: string, // Not strictly used for DB logic, but passed for route consistency
    commentId: string, 
    currentAuthUserId: string,
    currentUserRole: UserRole
): Promise<LikeDislikeResponse> => {
    
    // Pre-conditions: Check Backoffice setting `enableLikes`
    const settings = await getBackofficeSettings();
    const canLike = currentUserRole !== UserRole.Member || settings.enableLikes; 
    
    if (!canLike) {
        throw new ForbiddenError('Liking/disliking is currently disabled.');
    }

    return toggleCommentVote(commentId, currentAuthUserId, true); // true = isLikeAction
};

/**
 * Toggles a dislike on a comment.
 */
export const dislikeComment = async (
    postId: string, 
    commentId: string, 
    currentAuthUserId: string,
    currentUserRole: UserRole
): Promise<LikeDislikeResponse> => {
    
    // Pre-conditions: Check Backoffice setting `enableLikes`
    const settings = await getBackofficeSettings();
    const canDislike = currentUserRole !== UserRole.Member || settings.enableLikes; 
    
    if (!canDislike) {
        throw new ForbiddenError('Liking/disliking is currently disabled.');
    }

    return toggleCommentVote(commentId, currentAuthUserId, false); // false = isDislikeAction
};
