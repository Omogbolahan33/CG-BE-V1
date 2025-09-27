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
