import * as Symmetric from '../crypto/symmetric';

/**
 * Symmetric Encryption Section UI Logic
 */

let currentKey = '';
let currentCiphertext = '';

export function initSymmetricSection(): void {
    const inputField = document.getElementById('symmetric-input') as HTMLTextAreaElement;
    const keyField = document.getElementById('symmetric-key') as HTMLInputElement;
    const generateKeyBtn = document.getElementById('generate-symmetric-key') as HTMLButtonElement;
    const encryptBtn = document.getElementById('symmetric-encrypt') as HTMLButtonElement;
    const decryptBtn = document.getElementById('symmetric-decrypt') as HTMLButtonElement;
    const outputField = document.getElementById('symmetric-output') as HTMLDivElement;
    const copyBtn = document.getElementById('copy-symmetric') as HTMLButtonElement;

    // Generate Key
    generateKeyBtn.addEventListener('click', () => {
        const key = Symmetric.generateKey();
        keyField.value = key;
        currentKey = key;
    });

    // Encrypt
    encryptBtn.addEventListener('click', () => {
        const plaintext = inputField.value.trim();

        if (!plaintext) {
            showOutput(outputField, 'Please enter text to encrypt', 'error');
            return;
        }

        const key = keyField.value.trim();
        const result = Symmetric.encrypt(plaintext, key || undefined);

        currentKey = result.key;
        currentCiphertext = result.ciphertext;

        // Update key field if auto-generated
        if (!key) {
            keyField.value = result.key;
        }

        showOutput(outputField, result.ciphertext, 'success');
        copyBtn.style.display = 'inline-flex';
    });

    // Decrypt
    decryptBtn.addEventListener('click', () => {
        const key = keyField.value.trim();

        if (!currentCiphertext) {
            showOutput(outputField, 'Please encrypt text first', 'error');
            return;
        }

        if (!key) {
            showOutput(outputField, 'Please enter the encryption key', 'error');
            return;
        }

        const decrypted = Symmetric.decrypt(currentCiphertext, key);
        showOutput(outputField, decrypted, decrypted.startsWith('Error') ? 'error' : 'success');
    });

    // Copy to Clipboard
    copyBtn.addEventListener('click', async () => {
        const text = outputField.textContent || '';
        try {
            await navigator.clipboard.writeText(text);
            const originalText = copyBtn.textContent;
            copyBtn.textContent = '✓ Copied!';
            setTimeout(() => {
                copyBtn.textContent = originalText;
            }, 2000);
        } catch (err) {
            console.error('Failed to copy:', err);
        }
    });
}

function showOutput(element: HTMLDivElement, text: string, type: 'success' | 'error'): void {
    element.innerHTML = '';
    element.textContent = text;
    element.style.color = type === 'error' ? 'var(--color-accent-danger)' : 'var(--color-accent-success)';
}
