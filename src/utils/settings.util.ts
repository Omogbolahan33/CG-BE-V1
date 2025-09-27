// src/utils/settings.util.ts

import prisma from './prisma';
import { BackofficeSettings } from '@prisma/client'; // Import the base model type
import { EssentialBackofficeSettings } from '../types'; 


// A simple in-memory cache to reduce database load for frequently accessed settings
let settingsCache: EssentialBackofficeSettings | null = null;
const CACHE_DURATION_MS = 300000; // 5 minutes (300,000 ms)
let lastCacheUpdate = 0;


/**
 * Fetches the single BackofficeSettings record, creating it if it doesn't exist,
 * and caches the result.
 */
export const getBackofficeSettings = async (): Promise<EssentialBackofficeSettings> => {
    
    const now = Date.now();
    // 1. Check Cache
    if (settingsCache && (now - lastCacheUpdate) < CACHE_DURATION_MS) {
        return settingsCache;
    }

    // 2. Try to Find the Singleton Record
    // We use findFirst because we only expect one record.
    let settingsRecord: BackofficeSettings | null = await prisma.backofficeSettings.findFirst();

    // 3. Create Record if Not Found (First Run Logic)
    if (!settingsRecord) {
        console.warn("BackofficeSettings record not found. Creating the default singleton record.");
        try {
            // Create the record using all default values from the schema
            settingsRecord = await prisma.backofficeSettings.create({ data: {} });
        } catch (error) {
            // Handle concurrent creation attempt by another process
            settingsRecord = await prisma.backofficeSettings.findFirst(); 
            if (!settingsRecord) {
                // If it still fails, re-throw a more serious error
                throw new Error("Failed to create the BackofficeSettings singleton record.");
            }
        }
    }

    // 4. Extract and Cache Relevant Fields
    const essentialSettings: EssentialBackofficeSettings = {
        enablePostCreation: settingsRecord.enablePostCreation,
        enableAdvertisements: settingsRecord.enableAdvertisements,
    };
    
    settingsCache = essentialSettings;
    lastCacheUpdate = now;

    return essentialSettings;
};
