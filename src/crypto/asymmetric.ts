import nacl from 'tweetnacl';

/**
 * Asymmetric Encryption Module using NaCl (Curve25519)
 * Provides public-key encryption and decryption
 */

export interface KeyPair {
    publicKey: string;
    privateKey: string;
}

export interface EncryptionResult {
    ciphertext: string;
    nonce: string;
}

// Helper functions for encoding/decoding
function encodeBase64(arr: Uint8Array): string {
    return btoa(String.fromCharCode.apply(null, Array.from(arr)));
}

function decodeBase64(str: string): Uint8Array {
    return new Uint8Array(atob(str).split('').map(c => c.charCodeAt(0)));
}

function encodeUTF8(str: string): Uint8Array {
    return new TextEncoder().encode(str);
}

function decodeUTF8(arr: Uint8Array): string {
    return new TextDecoder().decode(arr);
}

/**
 * Generates a new key pair for asymmetric encryption
 * @returns Object containing base64-encoded public and private keys
 */
export function generateKeyPair(): KeyPair {
    const keyPair = nacl.box.keyPair();

    return {
        publicKey: encodeBase64(keyPair.publicKey),
        privateKey: encodeBase64(keyPair.secretKey),
    };
}

/**
 * Encrypts plaintext using recipient's public key
 * @param plaintext - The text to encrypt
 * @param recipientPublicKey - Base64-encoded public key
 * @param senderPrivateKey - Base64-encoded private key
 * @returns Object containing ciphertext and nonce
 */
export function encrypt(
    plaintext: string,
    recipientPublicKey: string,
    senderPrivateKey: string
): EncryptionResult {
    try {
        const messageUint8 = encodeUTF8(plaintext);
        const nonce = nacl.randomBytes(nacl.box.nonceLength);
        const publicKey = decodeBase64(recipientPublicKey);
        const privateKey = decodeBase64(senderPrivateKey);

        const encrypted = nacl.box(messageUint8, nonce, publicKey, privateKey);

        if (!encrypted) {
            throw new Error('Encryption failed');
        }

        return {
            ciphertext: encodeBase64(encrypted),
            nonce: encodeBase64(nonce),
        };
    } catch (error) {
        throw new Error(`Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
}

/**
 * Decrypts ciphertext using private key
 * @param ciphertext - Base64-encoded encrypted text
 * @param nonce - Base64-encoded nonce
 * @param senderPublicKey - Base64-encoded sender's public key
 * @param recipientPrivateKey - Base64-encoded recipient's private key
 * @returns Decrypted plaintext
 */
export function decrypt(
    ciphertext: string,
    nonce: string,
    senderPublicKey: string,
    recipientPrivateKey: string
): string {
    try {
        const encryptedMessage = decodeBase64(ciphertext);
        const nonceUint8 = decodeBase64(nonce);
        const publicKey = decodeBase64(senderPublicKey);
        const privateKey = decodeBase64(recipientPrivateKey);

        const decrypted = nacl.box.open(encryptedMessage, nonceUint8, publicKey, privateKey);

        if (!decrypted) {
            throw new Error('Decryption failed - invalid key or corrupted data');
        }

        return decodeUTF8(decrypted);
    } catch (error) {
        return `Error: ${error instanceof Error ? error.message : 'Decryption failed'}`;
    }
}
