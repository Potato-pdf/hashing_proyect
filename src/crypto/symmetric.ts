import CryptoJS from 'crypto-js';

/**
 * Symmetric Encryption Module using AES-256
 * Provides encryption and decryption functionality
 */

export interface EncryptionResult {
    ciphertext: string;
    key: string;
}

/**
 * Generates a random encryption key
 */
export function generateKey(): string {
    return CryptoJS.lib.WordArray.random(256 / 8).toString();
}

/**
 * Encrypts plaintext using AES-256
 * @param plaintext - The text to encrypt
 * @param key - The encryption key (auto-generated if not provided)
 * @returns Object containing ciphertext and key
 */
export function encrypt(plaintext: string, key?: string): EncryptionResult {
    const encryptionKey = key || generateKey();
    const ciphertext = CryptoJS.AES.encrypt(plaintext, encryptionKey).toString();

    return {
        ciphertext,
        key: encryptionKey,
    };
}

/**
 * Decrypts ciphertext using AES-256
 * @param ciphertext - The encrypted text
 * @param key - The decryption key
 * @returns Decrypted plaintext or error message
 */
export function decrypt(ciphertext: string, key: string): string {
    try {
        const bytes = CryptoJS.AES.decrypt(ciphertext, key);
        const plaintext = bytes.toString(CryptoJS.enc.Utf8);

        if (!plaintext) {
            throw new Error('Decryption failed - invalid key or corrupted data');
        }

        return plaintext;
    } catch (error) {
        return `Error: ${error instanceof Error ? error.message : 'Decryption failed'}`;
    }
}
