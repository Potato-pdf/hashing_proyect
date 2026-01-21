import bcrypt from 'bcryptjs';

/**
 * Bcrypt Password Hashing Module
 * Provides secure password hashing using bcrypt
 */

const DEFAULT_SALT_ROUNDS = 10;

/**
 * Hashes a password using bcrypt
 * @param password - The password to hash
 * @param saltRounds - Number of salt rounds (default: 10)
 * @returns Promise resolving to the hash string
 */
export async function hashPassword(
    password: string,
    saltRounds: number = DEFAULT_SALT_ROUNDS
): Promise<string> {
    try {
        const hash = await bcrypt.hash(password, saltRounds);
        return hash;
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
        return await bcrypt.compare(password, hash);
    } catch (error) {
        return false;
    }
}
