import CryptoJS from 'crypto-js';

/**
 * SHA-256 Password Hashing Module
 * Provides fast cryptographic hashing (not recommended for passwords in production)
 */

/**
 * Hashes a password using SHA-256
 * @param password - The password to hash
 * @returns The hash string
 */
export function hashPassword(password: string): string {
    try {
        return CryptoJS.SHA256(password).toString();
    } catch (error) {
        throw new Error(`SHA-256 hashing failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
}

/**
 * Hashes a password with salt using SHA-256
 * @param password - The password to hash
 * @param salt - Optional salt (auto-generated if not provided)
 * @returns Object containing hash and salt
 */
export function hashPasswordWithSalt(password: string, salt?: string): { hash: string; salt: string } {
    const usedSalt = salt || CryptoJS.lib.WordArray.random(128 / 8).toString();
    const hash = CryptoJS.SHA256(password + usedSalt).toString();

    return { hash, salt: usedSalt };
}
