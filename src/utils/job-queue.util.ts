// src/utils/job-queue.util.ts

import { Queue, Job } from 'bullmq';
import IORedis from 'ioredis';

// Concrete production configuration (requires environment variables)
const REDIS_CONNECTION = new IORedis({ 
    host: process.env.REDIS_HOST,
    port: parseInt(process.env.REDIS_PORT || '6379'),
    username: process.env.REDIS_USERNAME || 'default',
    password: process.env.REDIS_PASSWORD,
    maxRetriesPerRequest: null,
    
    // Required for the 'rediss://' protocol from Render
    tls: {
        rejectUnauthorized: false 
    }, 
    
});

const queueMap = new Map<string, Queue>();

const getQueue = (name: string): Queue => {
    if (!queueMap.has(name)) {
        const newQueue = new Queue(name, { connection: REDIS_CONNECTION });
        queueMap.set(name, newQueue);
    }
    return queueMap.get(name)!;
};

/**
 * Dispatches a job to the background queue using BullMQ.
 * @param jobName The unique name of the worker/job handler (e.g., 'NOTIFY_FOLLOWERS_OF_NEW_POST').
 * @param data The payload for the job.
 * @returns A BullMQ Job object promise.
 */
export const queueJob = (jobName: string, data: any): Promise<Job> => {
    const queue = getQueue('default-queue'); 
    
    // Add job with standard production options
    return queue.add(jobName, data, { 
        attempts: 3, 
        removeOnComplete: true 
    });
};
