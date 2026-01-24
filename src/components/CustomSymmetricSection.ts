/**
 * Custom Symmetric Encryption Section (CAHC - ChaCha-AES Hybrid Cipher)
 * Provides UI interactions for the custom encryption system
 */

import {
    encrypt,
    decrypt,
    generateSecureKey,
    getEncryptionInfo,
    type EncryptionParams,
    type DecryptionParams
} from '../crypto/custom-symmetric';

// UI Elements
let inputField: HTMLTextAreaElement;
let keyField: HTMLInputElement;
let iterationsField: HTMLInputElement;
let outputField: HTMLDivElement;
let encryptBtn: HTMLButtonElement;
let decryptBtn: HTMLButtonElement;
let generateKeyBtn: HTMLButtonElement;
let copyBtn: HTMLButtonElement;

// State
let lastEncryptionResult: any = null;

/**
 * Display result in output field
 */
function displayResult(result: string, isError: boolean = false): void {
    outputField.innerHTML = '';

    const resultElement = document.createElement('div');
    resultElement.className = isError ? 'output-error' : 'output-success';
    resultElement.style.wordBreak = 'break-all';
    resultElement.style.fontFamily = 'JetBrains Mono, monospace';
    resultElement.style.fontSize = '0.9rem';
    resultElement.style.lineHeight = '1.6';
    resultElement.style.color = isError ? '#dc2626' : '#000000'; // Red for error, black for success
    resultElement.style.backgroundColor = '#ffffff'; // White background
    resultElement.style.padding = '1rem';
    resultElement.style.borderRadius = '0.5rem';
    resultElement.style.border = isError ? '1px solid #dc2626' : '1px solid #e5e7eb';
    resultElement.textContent = result;

    outputField.appendChild(resultElement);
    copyBtn.style.display = isError ? 'none' : 'block';
}

/**
 * Display encryption metadata
 */
function displayMetadata(metadata: any): void {
    const metadataDiv = document.createElement('div');
    metadataDiv.className = 'encryption-metadata';
    metadataDiv.style.marginTop = '1rem';
    metadataDiv.style.padding = '0.75rem';
    metadataDiv.style.background = '#ffffff'; // White background
    metadataDiv.style.borderRadius = '0.5rem';
    metadataDiv.style.fontSize = '0.85rem';
    metadataDiv.style.fontFamily = 'JetBrains Mono, monospace';
    metadataDiv.style.border = '1px solid #e5e7eb'; // Light gray border

    metadataDiv.innerHTML = `
        <div style="margin-bottom: 0.5rem; color: #1f2937; font-weight: 600;">📊 Encryption Details</div>
        <div style="display: grid; grid-template-columns: auto 1fr; gap: 0.5rem; color: #374151;">
            <span>Iterations:</span><span style="color: #000000;">${metadata.iterations}</span>
            <span>Salt:</span><span style="color: #000000;">${metadata.salt.substring(0, 16)}...</span>
            <span>Key:</span><span style="color: #000000;">${metadata.key.substring(0, 16)}...</span>
            <span>Timestamp:</span><span style="color: #000000;">${new Date(metadata.timestamp).toLocaleString()}</span>
        </div>
    `;

    outputField.appendChild(metadataDiv);
}

/**
 * Handle encryption
 */
function handleEncrypt(): void {
    const plaintext = inputField.value.trim();

    if (!plaintext) {
        displayResult('⚠️ Error: Please enter text to encrypt', true);
        return;
    }

    try {
        // Get parameters
        const iterations = parseInt(iterationsField.value) || 10000;
        const masterKey = keyField.value.trim() || undefined;

        // Validate iterations
        if (iterations < 1000 || iterations > 100000) {
            displayResult('⚠️ Error: Iterations must be between 1,000 and 100,000', true);
            return;
        }

        const params: EncryptionParams = {
            iterations
        };

        // Show loading state
        encryptBtn.disabled = true;
        encryptBtn.textContent = 'Encrypting...';

        // Encrypt (with small delay for UI feedback)
        setTimeout(() => {
            try {
                const result = encrypt(plaintext, masterKey, params);
                lastEncryptionResult = result;

                // Update key field with the key used
                keyField.value = result.key;

                // IMPROVED UX: Automatically replace input with ciphertext for easy decryption
                inputField.value = result.ciphertext;

                // Add visual indicator that we're now in "decrypt mode"
                inputField.style.borderColor = '#10b981';
                setTimeout(() => {
                    inputField.style.borderColor = '';
                }, 2000);

                // Display result
                displayResult('✅ Encrypted successfully! The ciphertext has been placed in the input field above. Click "Decrypt" to verify.', false);
                displayMetadata(result);

                encryptBtn.disabled = false;
                encryptBtn.textContent = 'Encrypt with Custom Algorithm';
            } catch (error) {
                displayResult(`❌ Encryption Error: ${error instanceof Error ? error.message : 'Unknown error'}`, true);
                encryptBtn.disabled = false;
                encryptBtn.textContent = 'Encrypt with Custom Algorithm';
            }
        }, 100);

    } catch (error) {
        displayResult(`❌ Error: ${error instanceof Error ? error.message : 'Unknown error'}`, true);
        encryptBtn.disabled = false;
        encryptBtn.textContent = 'Encrypt with Custom Algorithm';
    }
}

/**
 * Handle decryption
 */
function handleDecrypt(): void {
    const ciphertext = inputField.value.trim();
    const key = keyField.value.trim();

    if (!ciphertext) {
        displayResult('⚠️ Error: Please enter ciphertext to decrypt', true);
        return;
    }

    if (!key) {
        displayResult('⚠️ Error: Please enter the decryption key', true);
        return;
    }

    try {
        // Show loading state
        decryptBtn.disabled = true;
        decryptBtn.textContent = 'Decrypting...';

        // Show encryption info
        try {
            const info = getEncryptionInfo(ciphertext);
            console.log('Encryption info:', info);
        } catch (e) {
            // Ignore if can't parse
        }

        // Decrypt (with small delay for UI feedback)
        setTimeout(() => {
            try {
                const params: DecryptionParams = {
                    ciphertext,
                    key
                };

                const plaintext = decrypt(params);

                // Clear input and show success with the decrypted text
                displayResult(`✅ Decrypted successfully!\n\nOriginal message: "${plaintext}"\n\n💡 Tip: Clear the input field to encrypt a new message.`, false);

                // Optionally clear the input to allow new encryption
                // inputField.value = '';

                decryptBtn.disabled = false;
                decryptBtn.textContent = 'Decrypt';
            } catch (error) {
                displayResult(`❌ ${error instanceof Error ? error.message : 'Decryption failed'}`, true);
                decryptBtn.disabled = false;
                decryptBtn.textContent = 'Decrypt';
            }
        }, 100);

    } catch (error) {
        displayResult(`❌ Error: ${error instanceof Error ? error.message : 'Unknown error'}`, true);
        decryptBtn.disabled = false;
        decryptBtn.textContent = 'Decrypt';
    }
}

/**
 * Generate a random key
 */
function handleGenerateKey(): void {
    const key = generateSecureKey(32);
    keyField.value = key;

    // Visual feedback
    keyField.style.background = 'rgba(34, 197, 94, 0.1)';
    setTimeout(() => {
        keyField.style.background = '';
    }, 500);
}

/**
 * Copy output to clipboard
 */
function handleCopy(): void {
    const text = outputField.textContent || '';

    navigator.clipboard.writeText(text).then(() => {
        const originalText = copyBtn.textContent;
        copyBtn.textContent = 'Copied ✓';
        copyBtn.style.background = 'rgba(34, 197, 94, 0.2)';

        setTimeout(() => {
            copyBtn.textContent = originalText;
            copyBtn.style.background = '';
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy:', err);
    });
}

/**
 * Initialize the custom symmetric section
 */
export function initCustomSymmetricSection(): void {
    // Get UI elements
    inputField = document.getElementById('custom-input') as HTMLTextAreaElement;
    keyField = document.getElementById('custom-key') as HTMLInputElement;
    iterationsField = document.getElementById('custom-iterations') as HTMLInputElement;
    outputField = document.getElementById('custom-output') as HTMLDivElement;
    encryptBtn = document.getElementById('custom-encrypt') as HTMLButtonElement;
    decryptBtn = document.getElementById('custom-decrypt') as HTMLButtonElement;
    generateKeyBtn = document.getElementById('generate-custom-key') as HTMLButtonElement;
    copyBtn = document.getElementById('copy-custom') as HTMLButtonElement;

    if (!inputField || !keyField || !outputField || !encryptBtn || !decryptBtn) {
        console.error('Required elements not found for custom symmetric section');
        return;
    }

    // Attach event listeners
    encryptBtn.addEventListener('click', handleEncrypt);
    decryptBtn.addEventListener('click', handleDecrypt);

    if (generateKeyBtn) {
        generateKeyBtn.addEventListener('click', handleGenerateKey);
    }

    if (copyBtn) {
        copyBtn.addEventListener('click', handleCopy);
    }

    console.log('✓ Custom symmetric encryption section initialized (CAHC)');
}
