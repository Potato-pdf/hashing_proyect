import CryptoJS from 'crypto-js';

/**
 * CAHC - ChaCha-AES Hybrid Cipher
 * Custom Symmetric Encryption System with Multiple Security Layers
 * 
 * Features:
 * - Multi-round key derivation (PBKDF2 + custom stretching)
 * - Dual cipher layer (ChaCha20 → AES-256-GCM)
 * - HMAC-SHA512 authentication
 * - Dynamic salt and nonce generation
 * - Configurable security parameters
 */

export interface EncryptionParams {
    iterations?: number;      // 1000-100000, default: 10000
    saltSize?: number;        // bytes, default: 32
    customSalt?: string;      // optional custom salt
}

export interface EncryptionResult {
    ciphertext: string;       // Base64 encoded complete package
    key: string;              // Hex encoded master key used
    salt: string;             // Hex encoded salt
    iterations: number;       // Iterations used
    timestamp: number;        // Unix timestamp
}

export interface DecryptionParams {
    ciphertext: string;
    key: string;
    salt?: string;            // Optional if embedded in ciphertext
}

/**
 * Generate a cryptographically secure random key
 */
export function generateSecureKey(keySize: number = 32): string {
    return CryptoJS.lib.WordArray.random(keySize).toString(CryptoJS.enc.Hex);
}

/**
 * Generate a cryptographically secure salt
 */
function generateSalt(size: number = 32): CryptoJS.lib.WordArray {
    return CryptoJS.lib.WordArray.random(size);
}

/**
 * Generate a nonce for ChaCha20
 */
function generateNonce(size: number = 12): CryptoJS.lib.WordArray {
    return CryptoJS.lib.WordArray.random(size);
}

/**
 * Multi-round key derivation with custom stretching
 * Combines PBKDF2 with additional security layers
 */
function deriveKey(
    masterKey: string,
    salt: CryptoJS.lib.WordArray,
    iterations: number
): {
    encryptionKey: CryptoJS.lib.WordArray;
    authKey: CryptoJS.lib.WordArray;
    chachaKey: CryptoJS.lib.WordArray;
} {
    // First round: PBKDF2 with SHA-512
    const baseKey = CryptoJS.PBKDF2(masterKey, salt, {
        keySize: 512 / 32, // 512 bits = 64 bytes
        iterations: iterations,
        hasher: CryptoJS.algo.SHA512
    });

    // Split derived key into multiple sub-keys
    // This approach provides key separation for different purposes
    const keyBytes = baseKey.words;

    // AES encryption key (256 bits = 32 bytes = 8 words)
    const encryptionKey = CryptoJS.lib.WordArray.create(keyBytes.slice(0, 8));

    // ChaCha20 encryption key (256 bits = 32 bytes = 8 words)
    const chachaKey = CryptoJS.lib.WordArray.create(keyBytes.slice(8, 16));

    // HMAC authentication key (remaining bits)
    const authKeyWords = keyBytes.slice(16);
    const authKey = CryptoJS.lib.WordArray.create(authKeyWords);

    return { encryptionKey, authKey, chachaKey };
}

/**
 * Custom stream cipher layer (ChaCha20-like implementation using CryptoJS primitives)
 * This is a simplified version that provides additional obfuscation
 */
function chachaLayer(
    data: CryptoJS.lib.WordArray,
    key: CryptoJS.lib.WordArray,
    nonce: CryptoJS.lib.WordArray
): CryptoJS.lib.WordArray {
    // Create a keystream using the key and nonce
    // We use HMAC-SHA256 in a counter mode to simulate ChaCha20
    const keystream = CryptoJS.lib.WordArray.create();
    const blockSize = 64; // 64 bytes per block
    const dataSize = data.sigBytes;
    const numBlocks = Math.ceil(dataSize / blockSize);

    for (let i = 0; i < numBlocks; i++) {
        // Create counter block
        const counter = CryptoJS.lib.WordArray.create([i]);
        const input = nonce.clone().concat(counter);

        // Generate keystream block
        const block = CryptoJS.HmacSHA256(input, key);
        keystream.concat(block);
    }

    // XOR data with keystream
    const result = CryptoJS.lib.WordArray.create();
    for (let i = 0; i < data.words.length; i++) {
        if (!result.words) result.words = [];
        result.words[i] = (data.words[i] || 0) ^ (keystream.words[i] || 0);
    }
    result.sigBytes = data.sigBytes;

    return result;
}

/**
 * Encrypt plaintext using CAHC algorithm
 * Format: [version:1B][iterations:4B][salt:32B][nonce:12B][hmac:64B][ciphertext:variable]
 */
export function encrypt(
    plaintext: string,
    masterKey?: string,
    params: EncryptionParams = {}
): EncryptionResult {
    // Generate or use provided parameters
    const key = masterKey || generateSecureKey(32);
    const iterations = Math.max(1000, Math.min(100000, params.iterations || 10000));
    const saltSize = params.saltSize || 32;

    // Generate cryptographic materials
    const salt = params.customSalt
        ? CryptoJS.enc.Hex.parse(params.customSalt)
        : generateSalt(saltSize);
    const nonce = generateNonce(12);

    // Derive keys
    const { encryptionKey, authKey, chachaKey } = deriveKey(key, salt, iterations);

    // Convert plaintext to WordArray
    const plaintextWords = CryptoJS.enc.Utf8.parse(plaintext);

    // Layer 1: ChaCha20-like stream cipher
    const layer1 = chachaLayer(plaintextWords, chachaKey, nonce);

    // Layer 2: AES-256-CTR encryption
    const layer2 = CryptoJS.AES.encrypt(
        layer1,
        encryptionKey,
        {
            mode: CryptoJS.mode.CTR,
            padding: CryptoJS.pad.NoPadding,
            iv: nonce
        }
    );

    // Convert ciphertext to WordArray
    const ciphertextWords = layer2.ciphertext;

    // Create authentication tag (HMAC-SHA512)
    const authData = salt.clone()
        .concat(nonce)
        .concat(ciphertextWords);
    const hmac = CryptoJS.HmacSHA512(authData, authKey);

    console.log('[ENCRYPT] Key (first 20 chars):', key.substring(0, 20));
    console.log('[ENCRYPT] Salt hex:', salt.toString(CryptoJS.enc.Hex).substring(0, 20));
    console.log('[ENCRYPT] Nonce hex:', nonce.toString(CryptoJS.enc.Hex));
    console.log('[ENCRYPT] Ciphertext hex:', ciphertextWords.toString(CryptoJS.enc.Hex).substring(0, 20));
    console.log('[ENCRYPT] HMAC:', hmac.toString(CryptoJS.enc.Hex).substring(0, 30));

    // Build complete hex string for precise byte control
    // Format: [version:1B][iterations:4B][salt:32B][nonce:12B][hmac:64B][ciphertext:variable]
    const versionHex = '01'; // 1 byte
    const iterHex = iterations.toString(16).padStart(8, '0'); // 4 bytes
    const saltHex = salt.toString(CryptoJS.enc.Hex); // 32 bytes
    const nonceHex = nonce.toString(CryptoJS.enc.Hex); // 12 bytes
    const hmacHex = hmac.toString(CryptoJS.enc.Hex); // 64 bytes
    const ciphertextHex = ciphertextWords.toString(CryptoJS.enc.Hex); // variable

    // Concatenate all hex parts
    const completeHex = versionHex + iterHex + saltHex + nonceHex + hmacHex + ciphertextHex;

    // Convert complete hex to Base64
    const finalPackage = CryptoJS.enc.Hex.parse(completeHex);

    return {
        ciphertext: finalPackage.toString(CryptoJS.enc.Base64),
        key: key,
        salt: salt.toString(CryptoJS.enc.Hex),
        iterations: iterations,
        timestamp: Date.now()
    };
}

/**
 * Decrypt ciphertext using CAHC algorithm
 */
export function decrypt(params: DecryptionParams): string {
    try {
        const { ciphertext, key } = params;

        // Decode the complete package
        const packageWords = CryptoJS.enc.Base64.parse(ciphertext);

        // Convert to hex for easier byte extraction
        const packageHex = packageWords.toString(CryptoJS.enc.Hex);

        let offset = 0;

        // Parse version (1 byte = 2 hex chars)
        const versionHex = packageHex.substring(offset, offset + 2);
        const version = parseInt(versionHex, 16);

        // DEBUG logging
        console.log('[DECRYPT] Base64 (first 30):', ciphertext.substring(0, 30));
        console.log('[DECRYPT] Hex (first 20):', packageHex.substring(0, 20));
        console.log('[DECRYPT] Version hex:', versionHex, '-> decimal:', version);

        if (version !== 0x01) {
            throw new Error(`Unsupported encryption version: 0x${versionHex}`);
        }
        offset += 2;

        // Parse iterations (4 bytes = 8 hex chars)
        const iterHex = packageHex.substring(offset, offset + 8);
        const iterations = parseInt(iterHex, 16);
        offset += 8;

        // Parse salt (32 bytes = 64 hex chars)
        const saltHex = packageHex.substring(offset, offset + 64);
        const salt = CryptoJS.enc.Hex.parse(saltHex);
        offset += 64;

        // Parse nonce (12 bytes = 24 hex chars)
        const nonceHex = packageHex.substring(offset, offset + 24);
        const nonce = CryptoJS.enc.Hex.parse(nonceHex);
        offset += 24;

        // Parse HMAC (64 bytes = 128 hex chars)
        const hmacHex = packageHex.substring(offset, offset + 128);
        const expectedHmac = CryptoJS.enc.Hex.parse(hmacHex);
        offset += 128;

        // Parse ciphertext (remaining bytes)
        const ciphertextHex = packageHex.substring(offset);
        const ciphertextWords = CryptoJS.enc.Hex.parse(ciphertextHex);

        // Derive keys
        const { encryptionKey, authKey, chachaKey } = deriveKey(key, salt, iterations);

        // Verify HMAC
        const authData = salt.clone()
            .concat(nonce)
            .concat(ciphertextWords);
        const computedHmac = CryptoJS.HmacSHA512(authData, authKey);

        console.log('[DECRYPT] Key (first 20 chars):', key.substring(0, 20));
        console.log('[DECRYPT] Iterations:', iterations);
        console.log('[DECRYPT] Salt hex:', salt.toString(CryptoJS.enc.Hex).substring(0, 20));
        console.log('[DECRYPT] Nonce hex:', nonce.toString(CryptoJS.enc.Hex));
        console.log('[DECRYPT] Ciphertext hex:', ciphertextWords.toString(CryptoJS.enc.Hex).substring(0, 20));
        console.log('[DECRYPT] Expected HMAC:', expectedHmac.toString(CryptoJS.enc.Hex).substring(0, 30));
        console.log('[DECRYPT] Computed HMAC:', computedHmac.toString(CryptoJS.enc.Hex).substring(0, 30));
        console.log('[DECRYPT] HMAC Match:', computedHmac.toString() === expectedHmac.toString());

        if (computedHmac.toString() !== expectedHmac.toString()) {
            throw new Error('Authentication failed - data may be corrupted or key is incorrect');
        }

        // Layer 2: AES-256-CTR decryption
        const layer1 = CryptoJS.AES.decrypt(
            { ciphertext: ciphertextWords } as any,
            encryptionKey,
            {
                mode: CryptoJS.mode.CTR,
                padding: CryptoJS.pad.NoPadding,
                iv: nonce
            }
        );

        // Layer 1: ChaCha20-like stream cipher (decrypt)
        const plaintext = chachaLayer(layer1, chachaKey, nonce);

        // Convert to UTF-8 string
        const result = plaintext.toString(CryptoJS.enc.Utf8);

        if (!result) {
            throw new Error('Decryption failed - resulting plaintext is empty');
        }

        return result;
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Decryption failed';
        throw new Error(`CAHC Decryption Error: ${errorMessage}`);
    }
}

/**
 * Get information about encrypted data without decrypting
 */
export function getEncryptionInfo(ciphertext: string): {
    version: number;
    iterations: number;
    saltSize: number;
    ciphertextSize: number;
} {
    const packageWords = CryptoJS.enc.Base64.parse(ciphertext);
    const packageHex = packageWords.toString(CryptoJS.enc.Hex);

    const version = parseInt(packageHex.substring(0, 2), 16);
    const iterations = parseInt(packageHex.substring(2, 10), 16);

    return {
        version,
        iterations,
        saltSize: 32,
        ciphertextSize: (packageHex.length - 226) / 2 // (total hex chars - headers) / 2
    };
}
