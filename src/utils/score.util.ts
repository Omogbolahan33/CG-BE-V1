/**
 * Calculates a sophisticated trending score for a post based on engagement and time decay.
 * @param likesCount Number of likes.
 * @param commentsCount Number of comments.
 * @param createdAt The time the post was created (Date object).
 * @returns The final trending score (number).
 */
export const calculateTrendingScore = (likesCount: number, commentsCount: number, createdAt: Date): number => {
    
    // Constants from Business Logic
    const GRAVITY = 1.5;
    const ALPHA = 1.3;
    const COMMENT_WEIGHT = 2;
    
    const now = new Date();
    // Time Since Post in hours, capped at a minimum to prevent division by zero or negative time.
    const timeSincePostHours = Math.max(0.1, (now.getTime() - createdAt.getTime()) / (1000 * 60 * 60));

    // 1. Engagement Score = (Likes * 1) + (Comments * 2)
    const engagementScore = (likesCount * 1) + (commentsCount * COMMENT_WEIGHT);

    // 2. Base Score = Engagement Score / ( (Time Since Post in hours) + 2 ) ^ Gravity(1.5)
    const baseScore = engagementScore / (Math.pow(timeSincePostHours + 2, GRAVITY));

    // 3. Velocity = Engagement Score / ( (Time Since Post in hours) + 1) ^ Alpha(1.3)
    const velocity = engagementScore / (Math.pow(timeSincePostHours + 1, ALPHA));

    // 4. Freshness Boost = random() * exp( -(Time Since Post in hours) / 2 )
    // A small random factor adds variety; exponential decay ensures it only affects new posts significantly.
    const freshnessBoost = Math.random() * Math.exp(-(timeSincePostHours / 2));
    
    // 5. Final Score = (Base Score * Velocity) + Freshness Boost
    const finalScore = (baseScore * velocity) + freshnessBoost;

    return finalScore;
};
