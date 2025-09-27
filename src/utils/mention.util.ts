/**
 * Parses content (typically HTML string) to find all unique usernames prefixed with '@'.
 * @param content The comment content string.
 * @returns An array of unique usernames found.
 */
export const parseMentions = (content: string): string[] => {
    // Basic regex to find strings following '@' that are valid usernames (alphanumeric and underscore)
    const mentionRegex = /@([a-zA-Z0-9_]+)/g;
    const matches = content.matchAll(mentionRegex);
    const usernames = new Set<string>();

    for (const match of matches) {
        // match[1] holds the captured group (the username)
        if (match[1]) {
            usernames.add(match[1]);
        }
    }

    return Array.from(usernames);
};
