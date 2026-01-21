import bcrypt from 'bcryptjs';

/**
 * Bcrypt Password Hashing Module
 * Provides secure password hashing using bcrypt
 */

/**
 * Hashes a password using bcrypt
 * @param password - The password to hash
 * @returns Promise resolving to the hash string
 */
export async function hashPassword(
    password: string,
): Promise<string> {
    try {
        // Bun provides native Argon2 hashing
        const hash = await Bun.password.hash(password, {
            algorithm: "bcrypt",
            cost: 4,
        });

        return hash;
    } catch (error) {
        throw new Error(`Argon2 hashing failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
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
        return await Bun.password.verify(password, hash);
    } catch (error) {
        return false;
    }
}
