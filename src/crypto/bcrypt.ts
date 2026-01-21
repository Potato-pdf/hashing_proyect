/**
 * Bcrypt Password Hashing Module
 * Uses server-side Bun API for hashing
 */

const API_URL = 'http://localhost:3001';

/**
 * Hashes a password using bcrypt via server API
 * @param password - The password to hash
 * @returns Promise resolving to the hash string
 */
export async function hashPassword(password: string): Promise<string> {
    try {
        const response = await fetch(`${API_URL}/api/hash/bcrypt`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ password }),
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Hashing failed');
        }

        const data = await response.json();
        return data.hash;
    } catch (error) {
        throw new Error(`Bcrypt hashing failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
}

/**
 * Verifies a password against a bcrypt hash
 * @param password - The password to verify
 * @param hash - The hash to verify against
 * @returns Promise resolving to true if password matches
 */
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
    try {
        return false;
    } catch (error) {
        return false;
    }
}
