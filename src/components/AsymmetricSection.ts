import * as Asymmetric from '../crypto/asymmetric';

/**
 * Asymmetric Encryption Section UI Logic
 */

let currentKeyPair: Asymmetric.KeyPair | null = null;
let currentEncryptionResult: Asymmetric.EncryptionResult | null = null;

export function initAsymmetricSection(): void {
    const generateKeyPairBtn = document.getElementById('generate-keypair') as HTMLButtonElement;
    const keyPairDisplay = document.getElementById('keypair-display') as HTMLDivElement;
    const publicKeyDisplay = document.getElementById('public-key') as HTMLDivElement;
    const privateKeyDisplay = document.getElementById('private-key') as HTMLDivElement;
    const inputField = document.getElementById('asymmetric-input') as HTMLTextAreaElement;
    const encryptBtn = document.getElementById('asymmetric-encrypt') as HTMLButtonElement;
    const decryptBtn = document.getElementById('asymmetric-decrypt') as HTMLButtonElement;
    const outputField = document.getElementById('asymmetric-output') as HTMLDivElement;
    const copyBtn = document.getElementById('copy-asymmetric') as HTMLButtonElement;

    // Generate Key Pair
    generateKeyPairBtn.addEventListener('click', () => {
        currentKeyPair = Asymmetric.generateKeyPair();

        publicKeyDisplay.textContent = currentKeyPair.publicKey;
        privateKeyDisplay.textContent = currentKeyPair.privateKey;
        keyPairDisplay.style.display = 'grid';

        showOutput(outputField, 'Key pair generated! You can now encrypt messages.', 'success');
    });

    // Encrypt
    encryptBtn.addEventListener('click', () => {
        const plaintext = inputField.value.trim();

        if (!plaintext) {
            showOutput(outputField, 'Please enter text to encrypt', 'error');
            return;
        }

        if (!currentKeyPair) {
            showOutput(outputField, 'Please generate a key pair first', 'error');
            return;
        }

        try {
            currentEncryptionResult = Asymmetric.encrypt(
                plaintext,
                currentKeyPair.publicKey,
                currentKeyPair.privateKey
            );

            const result = `${currentEncryptionResult.ciphertext}\n\nNonce: ${currentEncryptionResult.nonce}`;
            showOutput(outputField, result, 'success');
            copyBtn.style.display = 'inline-flex';
        } catch (error) {
            showOutput(outputField, error instanceof Error ? error.message : 'Encryption failed', 'error');
        }
    });

    // Decrypt
    decryptBtn.addEventListener('click', () => {
        if (!currentEncryptionResult) {
            showOutput(outputField, 'Please encrypt text first', 'error');
            return;
        }

        if (!currentKeyPair) {
            showOutput(outputField, 'Key pair not available', 'error');
            return;
        }

        const decrypted = Asymmetric.decrypt(
            currentEncryptionResult.ciphertext,
            currentEncryptionResult.nonce,
            currentKeyPair.publicKey,
            currentKeyPair.privateKey
        );

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
