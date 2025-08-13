class AuthButton extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
    }

    connectedCallback() {
        this.render();
        this.addEventListeners();
    }

    render() {
        const theme = this.getAttribute('theme') || 'light';
        const disabled = this.hasAttribute('disabled');

        this.shadowRoot.innerHTML = `
        <style>
            button {
                background: var(--auth-button-bg, #4285f4);
                color: var(--auth-button-color, white);
                border: var(--auth-button-border, none);
                border-radius: var(--auth-button-radius, 6px);
                padding: var(--auth-button-padding, 12px 24px);
                font-size: var(--auth-button-font-size, 14px);
                font-weight: var(--auth-button-font-weight, 500);
                font-family: var(--auth-button-font-family, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif);
                cursor: pointer;
                transition: all 0.2s ease;
                display: inline-flex;
                align-items: center;
                gap: 8px;
                text-decoration: none;
                min-height: 40px;
            }

            button:hover:not(:disabled) {
                background: var(--auth-button-hover-bg, #3367d6);
                transform: translateY(-1px);
                box-shadow: 0 2px 8px rgba(0,0,0,0.15);
            }

            button:active:not(:disabled) {
                transform: translateY(0);
            }

            button:disabled {
                opacity: 0.6;
                cursor: not-allowed;
            }

            .loading {
                width: 16px;
                height: 16px;
                border: 2px solid transparent;
                border-top: 2px solid currentColor;
                border-radius: 50%;
                animation: spin 1s linear infinite;
            }

            @keyframes spin {
                to { transform: rotate(360deg); }
            }

            .theme-dark {
                --auth-button-bg: #1a1a1a;
                --auth-button-hover-bg: #333;
            }

            .theme-outline {
                --auth-button-bg: transparent;
                --auth-button-color: #4285f4;
                --auth-button-border: 1px solid #4285f4;
            }
        </style>
        
        <button class="theme-${theme}" ${disabled ? 'disabled' : ''}>
            <span class="text">${this.textContent || 'Sign in'}</span>
        </button>
        `;
    }

    addEventListeners() {
        const button = this.shadowRoot.querySelector('button');

        button.addEventListener('click', async () => {
            if (button.disabled) return;

            const clientId = this.getAttribute('client-id');
            if (!clientId) {
                console.error('auth-button: client-id attribute is required');
                return;
            }

            const scope = this.getAttribute('scope');
            this.setLoading(true);

            try {
                const result = await window.AuthSDK.login({
                    clientId: clientId,
                    scope: scope
                });

                this.dispatchEvent(new CustomEvent('auth-success', {
                    detail: result,
                    bubbles: true
                }));

            } catch (error) {
                this.dispatchEvent(new CustomEvent('auth-error', {
                    detail: error.message,
                    bubbles: true
                }));
            } finally {
                this.setLoading(false);
            }
        });
    }

    setLoading(loading) {
        const button = this.shadowRoot.querySelector('button');
        const textSpan = this.shadowRoot.querySelector('.text');
        const originalText = this.textContent || 'Sign in';

        if (loading) {
            button.disabled = true;
            textSpan.innerHTML = '<span class="loading"></span> Signing in...';
        } else {
            button.disabled = false;
            textSpan.textContent = originalText;
        }
    }
}

customElements.define('auth-button', AuthButton);