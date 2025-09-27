// src/services/post.service.ts

import prisma from '../utils/prisma';
import type { Post } from '../types'; // Assuming Post type is imported
import { calculateTrendingScore } from '../utils/score.util';
import { BadRequestError } from '../errors/BadRequestError';
// Assuming sanitizeHtml is available (e.g., from 'sanitize-html')
import * as sanitizeHtml from 'sanitize-html'; 

// Define the required filter/sort input types for clarity in the service layer
export interface GetPostsFilters {
    viewMode: 'discussions' | 'adverts';
    sortMode?: 'top' | 'trending' | 'new';
    advertSort?: 'newest' | 'price_asc' | 'price_desc';
    limit?: number;
    offset?: number;
    minPrice?: number;
}

/**
 * API: Get Posts
 * @description Fetches a list of posts with filtering, sorting, and pagination.
 * @param filters The query parameters for filtering and sorting.
 * @returns { posts: Post[], total: number }
 */
export const getPosts = async (filters: GetPostsFilters): Promise<{ posts: Post[], total: number }> => {
    
    const { 
        viewMode, 
        sortMode = 'new', 
        advertSort = 'newest', 
        limit = 20, 
        offset = 0, 
        minPrice 
    } = filters;

    // --- 1. Base Query Definition ---
    const where: Prisma.PostWhereInput = {
        // Simple filtering based on viewMode (assuming an 'isAdvert' or 'type' field in Post)
        // Adjust this logic based on your actual Post model structure
        isAdvert: viewMode === 'adverts' ? true : { not: true },
        
        // Filter for adverts based on price if minPrice is provided
        ...(viewMode === 'adverts' && minPrice !== undefined && minPrice >= 0 && {
            price: { gte: minPrice }
        })
    };

    // --- 2. Sorting Logic ---
    let orderBy: Prisma.PostOrderByWithRelationInput = {};
    let posts: Post[];
    let total: number;

    const standardSelect = {
        id: true,
        createdAt: true,
        likesCount: true,
        commentsCount: true,
        content: true,
        // ... include all fields required for the client
    };

    if (viewMode === 'adverts') {
        // @businessLogic: Advert sorting
        switch (advertSort) {
            case 'price_asc':
                orderBy = { price: 'asc' };
                break;
            case 'price_desc':
                orderBy = { price: 'desc' };
                break;
            case 'newest':
            default:
                orderBy = { createdAt: 'desc' };
                break;
        }
    } else { // viewMode === 'discussions'
        switch (sortMode) {
            case 'new':
                orderBy = { createdAt: 'desc' };
                break;
                
            case 'top':
            {
                // @businessLogic: Sorting Logic ('top')
                // 1. Calculate engagement score in-memory (or ideally via a computed field in DB)
                // 2. Prioritize pinned posts from the last 24 hours.
                
                // Fetch all potential posts for in-memory scoring and custom sorting
                const allPosts = await prisma.post.findMany({
                    where,
                    select: {
                        ...standardSelect,
                        pinnedAt: true,
                    },
                    // Fetch more than 'limit' to correctly apply top/trending logic before pagination
                    // A larger initial fetch size (e.g., 100) is often used here.
                });
                
                // Calculate score and sort
                posts = allPosts
                    .map(post => ({
                        ...post,
                        engagementScore: post.likesCount + post.commentsCount,
                    }))
                    .sort((a, b) => {
                        const now = new Date();
                        const twentyFourHoursAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

                        // Pinned posts within 24 hours always come first
                        const aPinnedRecent = a.pinnedAt && a.pinnedAt > twentyFourHoursAgo;
                        const bPinnedRecent = b.pinnedAt && b.pinnedAt > twentyFourHoursAgo;

                        if (aPinnedRecent && !bPinnedRecent) return -1;
                        if (!aPinnedRecent && bPinnedRecent) return 1;
                        
                        // Otherwise, sort by Engagement Score
                        return b.engagementScore - a.engagementScore;
                    });
                    
                // Total is the total number of posts that matched the 'where' clause
                total = posts.length;
                // Apply final pagination
                posts = posts.slice(offset, offset + limit);
                break;
            }
                
            case 'trending':
            {
                // @businessLogic: Sorting Logic ('trending')
                // Similar to 'top', we must fetch and calculate the score in-memory.
                const allPosts = await prisma.post.findMany({
                    where,
                    select: {
                        ...standardSelect,
                    },
                    // Fetch a reasonable amount for trending calculation
                });

                // Calculate the Final Score using the utility function
                posts = allPosts
                    .map(post => ({
                        ...post,
                        trendingScore: calculateTrendingScore(post.likesCount, post.commentsCount, post.createdAt),
                    }))
                    .sort((a, b) => b.trendingScore - a.trendingScore); // Sort descending by score
                
                total = posts.length;
                // Apply final pagination
                posts = posts.slice(offset, offset + limit);
                break;
            }
                
            default:
                orderBy = { createdAt: 'desc' };
                break;
        }
    }

    // --- 3. Execute Query (Only if standard DB sorting/pagination is used) ---
    if (sortMode === 'new' || viewMode === 'adverts') {
        [posts, total] = await prisma.$transaction([
            prisma.post.findMany({
                where,
                orderBy,
                take: limit,
                skip: offset,
                select: standardSelect,
            }),
            prisma.post.count({ where }),
        ]);
    }


    // --- 4. Security & Cleanup ---
    // @security: Sanitize HTML content
    const sanitizedPosts = posts.map(post => ({
        ...post,
        // The sanitize-html package is typically used here with safe configuration
        content: sanitizeHtml(post.content, {
            allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img', 'h1', 'h2']),
            allowedAttributes: {
                ...sanitizeHtml.defaults.allowedAttributes,
                'a': ['href', 'name', 'target'],
                'img': ['src', 'srcset', 'alt', 'title', 'width', 'height', 'loading'],
            },
        }),
    })) as Post[]; // Cast back to Post[] type
    
    return { posts: sanitizedPosts, total };
};
