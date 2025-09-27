// post.service.ts (or comment.service.ts)

import prisma from '../utils/prisma';
import { Post, Comment, AuthUser } from '../types';
import { ForbiddenError } from '../errors/ForbiddenError';
import { NotFoundError } from '../errors/NotFoundError';
import { sanitizeCommentContent } from '../utils/sanitize-html'; // Assumed utility
import { getBackofficeSettings } from '../utils/settings.util'; // Assumed utility
import { parseMentions } from '../utils/mention.util'; // Assumed utility
import { queueJob } from '../utils/job-queue.util'; // Assumed utility
import { UserRole } from '@prisma/client';

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
    const [post, parentComment, settings] = await Promise.all([
        prisma.post.findUnique({
            where: { id: postId },
            select: { 
                id: true, 
                authorId: true, 
                isCommentingRestricted: true,
                followedBy: { select: { id: true } } // Fetch followers
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
    // **Security:** Sanitize content
    const sanitizedContent = sanitizeCommentContent(commentData.content);
    const mentionedUsernames = parseMentions(sanitizedContent); // Parse for @mentions

    const newComment = await prisma.$transaction(async (tx) => {
        
        // 3.1. Create the Comment record
        const createdComment = await tx.comment.create({
            data: {
                content: sanitizedContent,
                media: commentData.media as Prisma.JsonArray, // Assuming media is stored as JSON array
                postId: postId,
                authorId: currentAuthUserId,
                parentId: parentId,
            } as Prisma.CommentCreateInput // Cast for complex input types
        }) as unknown as Comment; // Cast to your simple Comment type

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
    
    // Set to track users who have already received a notification to prevent duplicates
    const notifiedUserIds = new Set<string>([currentAuthUserId]); // Exclude commenter

    // --- Prepare Notification Queue Data ---
    const notificationsToQueue: any[] = [];
    let parentCommentAuthorId: string | null = parentComment?.authorId || null;

    // 4.1. Create 'Commented on Post' entry in user's ActivityLog
    queueJob('CREATE_ACTIVITY_LOG', {
        type: 'COMMENTED_ON_POST',
        userId: currentAuthUserId,
        postId: postId,
        commentId: newComment.id
    });
    
    // 4.2. Mentions
    if (mentionedUsernames.length > 0) {
        const mentionedUsers = await prisma.user.findMany({
            where: { username: { in: mentionedUsernames } },
            select: { id: true }
        });

        mentionedUsers.forEach(user => {
            if (!notifiedUserIds.has(user.id)) {
                notificationsToQueue.push({
                    type: 'MENTION',
                    recipientId: user.id,
                    details: { postId, commentId: newComment.id, commenterId: currentAuthUserId }
                });
                notifiedUserIds.add(user.id);
            }
        });
    }

    // 4.3. Replies (Parent Comment Author)
    if (parentId && parentCommentAuthorId && !notifiedUserIds.has(parentCommentAuthorId)) {
        notificationsToQueue.push({
            type: 'COMMENT_REPLY',
            recipientId: parentCommentAuthorId,
            details: { postId, commentId: newComment.id, commenterId: currentAuthUserId }
        });
        notifiedUserIds.add(parentCommentAuthorId);
    }
    
    // 4.4. Post Author
    if (post.authorId !== currentAuthUserId && !notifiedUserIds.has(post.authorId)) {
        notificationsToQueue.push({
            type: 'NEW_COMMENT_ON_POST',
            recipientId: post.authorId,
            details: { postId, commentId: newComment.id, commenterId: currentAuthUserId }
        });
        notifiedUserIds.add(post.authorId);
    }

    // 4.5. Post Followers
    post.followedBy.forEach(user => {
        if (!notifiedUserIds.has(user.id)) {
            notificationsToQueue.push({
                type: 'FOLLOWED_POST_COMMENT',
                recipientId: user.id,
                details: { postId, commentId: newComment.id, commenterId: currentAuthUserId }
            });
            notifiedUserIds.add(user.id);
        }
    });

    // Queue all collected notifications
    notificationsToQueue.forEach(job => queueJob('SEND_NOTIFICATION', job));

    return newComment;
};
