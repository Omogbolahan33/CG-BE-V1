import sanitizeHtml from 'sanitize-html'; 

// Define a robust configuration for post content
const sanitizationConfig = {
    // Basic formatting tags
    allowedTags: sanitizeHtml.defaults.allowedTags.concat([
        'img', 'h1', 'h2', 'h3', 'p', 'span', 'br', 'hr', 'blockquote', 'code', 'pre'
    ]),
    // Allow necessary attributes for links and images
    allowedAttributes: {
        ...sanitizeHtml.defaults.allowedAttributes,
        'a': ['href', 'name', 'target', 'rel'],
        'img': ['src', 'srcset', 'alt', 'title', 'width', 'height', 'loading'],
        'span': ['style'], // Allows for basic inline styling like color/font-size
    },
    // Enforce safe link targets
    disallowedTagsMode: 'discard',
    enforceHtmlBoundary: true,
    transformTags: {
        'a': sanitizeHtml.defaultTransform,
        'img': (tagName, attribs) => ({
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
