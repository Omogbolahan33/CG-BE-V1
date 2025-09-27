// src/utils/comment-nesting.util.ts

// Define the structure of a raw comment from Prisma
interface FlatComment {
    id: string;
    content: string;
    parentId: string | null;
    // Include other necessary fields like author, timestamp, etc.
    // ...
    // These fields are needed for the function to work correctly
    [key: string]: any; 
}

// Define the structure of a nested comment (the output)
export interface NestedComment extends FlatComment {
    replies: NestedComment[];
}

/**
 * Transforms a flat list of comments into a nested array representing comment threads.
 * @param comments A flat array of comments, where each can have a parentId.
 * @returns A nested array of comments (top-level comments with their replies array populated).
 */
export const nestComments = (comments: FlatComment[]): NestedComment[] => {
    
    // 1. Create a map of comments for quick lookups and mutation.
    const commentMap = new Map<string, NestedComment>();
    let topLevelComments: NestedComment[] = [];

    // 2. First pass: Initialize map and identify top-level comments.
    comments.forEach(comment => {
        const nestedComment: NestedComment = { ...comment, replies: [] };
        commentMap.set(comment.id, nestedComment);

        if (!comment.parentId) {
            topLevelComments.push(nestedComment);
        }
    });

    // 3. Second pass: Build the hierarchy.
    comments.forEach(comment => {
        if (comment.parentId) {
            const parent = commentMap.get(comment.parentId);
            const reply = commentMap.get(comment.id);

            if (parent && reply) {
                // Ensure the reply is added to the parent's replies array
                parent.replies.push(reply);
            }
            // Note: Orphaned comments (parent not found) are automatically dropped here.
        }
    });

    return topLevelComments;
};
