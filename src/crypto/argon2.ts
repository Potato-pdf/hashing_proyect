/**
 * Argon2 Password Hashing Module
 * Uses Bun's native Argon2 implementation
 */

export interface Argon2Options {
    timeCost?: number;
    memoryCost?: number;
    parallelism?: number;
}

/**
 * Hashes a password using Argon2id (Bun native)
 * @param password - The password to hash
 * @param options - Optional Argon2 parameters
 * @returns Promise resolving to the hash string
 */
export async function hashPassword(
    password: string,
    options: Argon2Options = {}
): Promise<string> {
    try {
        // Bun provides native Argon2 hashing
        const hash = await Bun.password.hash(password, {
            algorithm: 'argon2id',
            timeCost: options.timeCost || 3,
            memoryCost: options.memoryCost || 65536, // 64 MiB
        });

        return hash;
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
        return await Bun.password.verify(password, hash);
    } catch (error) {
        return false;
    }
}
