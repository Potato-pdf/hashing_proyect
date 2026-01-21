import * as Argon2 from '../crypto/argon2';
import * as Bcrypt from '../crypto/bcrypt';
import * as SHA256 from '../crypto/sha256';

/**
 * Password Hashing Section UI Logic
 */

interface HashHistoryItem {
    algorithm: string;
    hash: string;
    timestamp: Date;
}

let selectedAlgorithm: 'argon2' | 'bcrypt' | 'sha256' = 'argon2';
let hashHistory: HashHistoryItem[] = [];

export function initHashingSection(): void {
    const inputField = document.getElementById('hash-input') as HTMLInputElement;
    const hashBtn = document.getElementById('hash-password') as HTMLButtonElement;
    const clearHistoryBtn = document.getElementById('clear-history') as HTMLButtonElement;
    const historyList = document.getElementById('history-list') as HTMLDivElement;
    const algorithmButtons = document.querySelectorAll('.algorithm-btn');

    // Algorithm Selection
    algorithmButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            algorithmButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            selectedAlgorithm = btn.getAttribute('data-algorithm') as 'argon2' | 'bcrypt' | 'sha256';
        });
    });

    // Hash Password
    hashBtn.addEventListener('click', async () => {
        const password = inputField.value.trim();

        if (!password) {
            alert('Please enter a password to hash');
            return;
        }

        hashBtn.disabled = true;
        hashBtn.textContent = 'Hashing...';

        try {
            let hash: string;

            switch (selectedAlgorithm) {
                case 'argon2':
                    hash = await Argon2.hashPassword(password);
                    break;
                case 'bcrypt':
                    hash = await Bcrypt.hashPassword(password);
                    break;
                case 'sha256':
                    hash = SHA256.hashPassword(password);
                    break;
            }

            // Add to history
            hashHistory.unshift({
                algorithm: selectedAlgorithm.toUpperCase(),
                hash,
                timestamp: new Date(),
            });

            // Update UI
            renderHistory(historyList);
            inputField.value = '';
        } catch (error) {
            alert(`Hashing failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        } finally {
            hashBtn.disabled = false;
            hashBtn.innerHTML = '<span class="btn-icon">🔨</span> Hash Password';
        }
    });

    // Clear History
    clearHistoryBtn.addEventListener('click', () => {
        if (hashHistory.length === 0) return;

        if (confirm('Are you sure you want to clear the hashing history?')) {
            hashHistory = [];
            renderHistory(historyList);
        }
    });

    // Allow Enter key to hash
    inputField.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            hashBtn.click();
        }
    });
}

function renderHistory(container: HTMLDivElement): void {
    if (hashHistory.length === 0) {
        container.innerHTML = '<div class="history-empty">No hashes yet. Hash a password to see it here.</div>';
        return;
    }

    container.innerHTML = hashHistory.map(item => `
    <div class="history-item">
      <div class="history-header">
        <span class="history-algorithm">${item.algorithm}</span>
        <span class="history-timestamp">${formatTimestamp(item.timestamp)}</span>
      </div>
      <div class="history-hash">${item.hash}</div>
    </div>
  `).join('');
}

function formatTimestamp(date: Date): string {
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);

    if (seconds < 60) return 'Just now';
    if (minutes < 60) return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`;

    return date.toLocaleString();
}
