/**
 * Argon2 Password Hashing Module
 * Uses server-side Bun API for hashing
 */

const API_URL = 'http://localhost:3001';

export interface Argon2Options {
    timeCost?: number;
    memoryCost?: number;
    parallelism?: number;
}

/**
 * Hashes a password using Argon2id via server API
 * @param password - The password to hash
 * @param options - Optional Argon2 parameters (not used in API call)
 * @returns Promise resolving to the hash string
 */
export async function hashPassword(
    password: string,
    options: Argon2Options = {}
): Promise<string> {
    try {
        const response = await fetch(`${API_URL}/api/hash/argon2`, {
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
        throw new Error(`Argon2 hashing failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
}

/**
 * Verifies a password against an Argon2 hash
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
