// src/services/post.service.ts

import prisma from '../utils/prisma';
import { Prisma } from '@prisma/client'; 
import { calculateTrendingScore } from '../utils/score.util';
import { sanitizePostContent } from '../utils/sanitize-html'; // <-- Correct, singular import of wrapper
import { BadRequestError } from '../errors/BadRequestError'; // <-- Required for input validation
import { Post, GetPostsFilters } from '../types'; 

/**
 * Defines the minimum required fields from the Post model for fetching.
 * Includes fields necessary for sorting (likesCount, pinnedAt, price) and presentation.
 */
const POST_SELECT_FIELDS = {
    id: true,
    createdAt: true,
    updatedAt: true,
    content: true,
    likesCount: true,
    commentsCount: true,
    pinnedAt: true,
    price: true,
    isAdvert: true, 
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
    let fetchedPosts: Post[];
    let total: number;
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
                orderBy = { createdAt: 'desc' };
                break;
        }
    } else { // viewMode === 'discussions'
        switch (sortMode) {
            case 'new':
                orderBy = { createdAt: 'desc' };
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
                            trendingScore: calculateTrendingScore(post.likesCount, post.commentsCount, post.createdAt) 
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
                orderBy = { createdAt: 'desc' };
                break;
        }
    }

    // --- 4. Execute Query (Standard DB path) ---
    if (shouldQueryFromDB) {
        // CORRECTION: Use $transaction for consistency in fetching count and data
        [fetchedPosts, total] = await prisma.$transaction([
            prisma.post.findMany({
                where,
                orderBy,
                take: limit,
                skip: offset,
                select: POST_SELECT_FIELDS,
            }) as Promise<Post[]>,
            prisma.post.count({ where }),
        ]);
    }


    // --- 5. Security & Cleanup ---
    // CORRECTION: Use the dedicated sanitizePostContent wrapper function
    const sanitizedPosts = fetchedPosts.map(post => ({
        ...post,
        content: sanitizePostContent(post.content),
    })) as Post[]; 
    
    return { posts: sanitizedPosts, total };
};
