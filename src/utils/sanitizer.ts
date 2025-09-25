// src/utils/sanitizer.ts

import { JSDOM } from 'jsdom';
import DOMPurify from 'dompurify';

// Initialize DOMPurify for server-side use
const window = new JSDOM('').window as unknown as Window;
const purify = DOMPurify(window);

/**
 * Sanitizes a string to prevent XSS attacks.
 * @param dirty The string content to sanitize.
 * @returns The sanitized, safe string.
 */
export const sanitize = (dirty: string): string => {
  // Use a strict configuration, allowing no HTML elements
  // For posts/comments, you might allow a few like <b>, <i>, <a>, but for security, 
  // we start with the strictest possible setting.
  const clean = purify.sanitize(dirty, {ALLOWED_TAGS: [], ALLOWED_ATTR: []});
  return clean;
};

/**
 * Trims and sanitizes a string for use as a database identifier.
 * @param identifier The identifier string (username or email).
 * @returns The trimmed and sanitized identifier.
 */
export const cleanIdentifier = (identifier: string): string => {
  if (!identifier) return '';
  // Trim whitespace and then sanitize the string
  return sanitize(identifier.trim());
};
