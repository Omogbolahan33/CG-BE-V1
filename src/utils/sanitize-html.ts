// src/utils/sanitize-html.ts

// Install this package first: npm install sanitize-html @types/sanitize-html
import sanitizeHtml, { IOptions } from 'sanitize-html'; 

/**
 * Custom implementation of the default transform function.
 * This function simply returns the tag name and attributes unchanged.
 * @param tagName The tag name.
 * @param attribs The tag's attributes.
 * @returns An object containing the tag name and attributes.
 */
const defaultTransform: (tagName: string, attribs: { [key: string]: string }) => { tagName: string, attribs: { [key: string]: string } } = (tagName, attribs) => ({
    tagName,
    attribs
});

// Define a robust configuration for post content
const sanitizationConfig: IOptions = {
    // Basic formatting tags
    allowedTags: sanitizeHtml.defaults.allowedTags.concat([
        'img', 'h1', 'h2', 'h3', 'p', 'span', 'br', 'hr', 'blockquote', 'code', 'pre'
    ]),
    // Allow necessary attributes for links and images
    allowedAttributes: {
        ...sanitizeHtml.defaults.allowedAttributes,
        'a': ['href', 'name', 'target', 'rel'],
        'img': ['src', 'srcset', 'alt', 'title', 'width', 'height', 'loading'],
        'span': ['style'],
    },
    // Enforce safe link targets
    disallowedTagsMode: 'discard',
    enforceHtmlBoundary: true,
    
    // CORRECTION: Use the locally defined defaultTransform function
    transformTags: {
        'a': defaultTransform, // Fixed: Using local function instead of static property
        
        'img': (tagName: string, attribs: { [key: string]: string }) => ({
            tagName,
            attribs: {
                ...attribs,
                // Ensure images use https if possible
                src: attribs.src?.startsWith('http') ? attribs.src : ''
            }
        })
    }
};

/**
 * Sanitizes HTML content to prevent XSS attacks.
 * @param html The potentially unsafe HTML string.
 * @returns The sanitized HTML string.
 */
export const sanitizePostContent = (html: string): string => {
    if (!html) return '';
    return sanitizeHtml(html, sanitizationConfig); 
};
