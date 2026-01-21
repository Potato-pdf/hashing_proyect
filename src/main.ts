/**
 * Main Application Entry Point
 * Initializes all cryptography demonstration sections with tab navigation
 */

import { initSymmetricSection } from './components/SymmetricSection';
import { initAsymmetricSection } from './components/AsymmetricSection';
import { initHashingSection } from './components/HashingSection';
import { initCustomHashSection } from './components/CustomHashSection';

// Tab Navigation Logic
function initTabNavigation(): void {
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabName = button.getAttribute('data-tab');

            // Remove active class from all buttons and contents
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));

            // Add active class to clicked button and corresponding content
            button.classList.add('active');
            const targetContent = document.getElementById(`tab-${tabName}`);
            if (targetContent) {
                targetContent.classList.add('active');
            }
        });
    });
}

// Initialize application when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    console.log('🔐 Cryptography Laboratory Starting...');

    try {
        // Initialize tab navigation
        initTabNavigation();
        console.log('✓ Tab navigation initialized');

        // Initialize all sections
        initSymmetricSection();
        console.log('✓ Symmetric encryption section initialized');

        initAsymmetricSection();
        console.log('✓ Asymmetric encryption section initialized');

        initHashingSection();
        console.log('✓ Password hashing section initialized');

        initCustomHashSection();
        console.log('✓ Custom hashing section initialized');

        console.log('🎉 Application ready!');
    } catch (error) {
        console.error('❌ Application initialization failed:', error);
    }
});
