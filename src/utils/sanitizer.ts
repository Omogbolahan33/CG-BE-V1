// src/utils/sanitizer.ts

import { JSDOM } from 'jsdom';
import DOMPurify from 'dompurify';

// 1. Initialize JSDOM and capture the window object.
const { window } = new JSDOM('');

// 2. Initialize DOMPurify for server-side use.
// We cast the window object to 'any' to bypass the strict type mismatch 
// between jsdom's Window and DOMPurify's required WindowLike type.
const purify = DOMPurify(window as any); // <-- **FIX IS HERE**

/**
 * Sanitizes a string to prevent XSS attacks.
 * @param dirty The string content to sanitize.
 * @returns The sanitized, safe string.
 */
export const sanitize = (dirty: string): string => {
  // Use a strict configuration, allowing no HTML elements
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
