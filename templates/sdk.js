(function () {
    const AUTH_SERVER = "{{ auth_server_url }}";

    class AuthSDK {
        constructor() {
            this.popup = null;
        }

        login(config) {
            return new Promise((resolve, reject) => {
                if (this.popup && !this.popup.closed) {
                    this.popup.focus();
                    return;
                }

                const state = this.generateState();
                const params = new URLSearchParams({
                    response_type: "code",
                    client_id: config.clientId,
                    redirect_uri: `${AUTH_SERVER}/success`,
                    scope: config.scope || "openid profile",
                    state: state
                });

                const authUrl = `${AUTH_SERVER}/authorize?${params}`;
                this.popup = this.openPopup(authUrl);

                this.setupHandlers(resolve, reject);
            });
        }

        register(config) {
            return new Promise((resolve, reject) => {
                const state = this.generateState();
                const params = new URLSearchParams({
                    client_id: config.clientId,
                    redirect_uri: `${AUTH_SERVER}/success`,
                    scope: config.scope || "openid profile",
                    state: state
                });

                const registerUrl = `${AUTH_SERVER}/register?${params}`;
                this.popup = this.openPopup(registerUrl);

                this.setupHandlers(resolve, reject);
            });
        }

        setupHandlers(resolve, reject) {
            const messageHandler = (event) => {
                if (event.origin !== AUTH_SERVER) return;

                if (event.data.type === "AUTH_SUCCESS") {
                    this.cleanup(messageHandler);
                    resolve({ code: event.data.code, state: event.data.state });
                }

                if (event.data.type === "AUTH_ERROR") {
                    this.cleanup(messageHandler);
                    reject(new Error(event.data.error));
                }
            };

            window.addEventListener("message", messageHandler);

            const checkClosed = setInterval(() => {
                if (this.popup.closed) {
                    clearInterval(checkClosed);
                    window.removeEventListener("message", messageHandler);
                    reject(new Error("Authentication cancelled"));
                }
            }, 1000);
        }

        cleanup(messageHandler) {
            window.removeEventListener("message", messageHandler);
            this.popup.close();
        }

        openPopup(url) {
            const width = 500;
            const height = 600;
            const left = Math.round((screen.width / 2) - (width / 2));
            const top = Math.round((screen.height / 2) - (height / 2));

            const features = [
                `width=${width}`,
                `height=${height}`,
                `left=${left}`,
                `top=${top}`,
                "scrollbars=yes",
                "resizable=yes",
                "status=no",
                "toolbar=no",
                "menubar=no",
                "location=no"
            ].join(",");

            return window.open(url, "auth-popup", features);
        }

        generateState() {
            return Math.random().toString(36).substring(2, 15) +
                Math.random().toString(36).substring(2, 15);
        }
    }

    class AuthButton extends HTMLElement {
        constructor() {
            super();
            this.attachShadow({ mode: "open" });
        }

        connectedCallback() {
            this.render();
            this.addEventListeners();
        }

        getButtonText() {
            const customText = this.textContent?.trim();
            if (customText) {
                return customText;
            }

            const type = this.getAttribute("type") || "login";
            const action = type === "register" ? "Register" : "Sign in";

            return `${action} with <span class="brand">sjallabong</span>`;
        }

        render() {
            const theme = this.getAttribute("theme") || "light";
            const disabled = this.hasAttribute("disabled");

            this.shadowRoot.innerHTML = `
                <link href="https://fonts.googleapis.com/css2?family=Josefin+Sans:wght@700&display=swap" rel="stylesheet">
                <style>
                    button {
                        background: var(--auth-button-bg, #4285f4);
                        color: var(--auth-button-color, white);
                        border: var(--auth-button-border, none);
                        border-radius: var(--auth-button-radius, 8px);
                        padding: var(--auth-button-padding, 14px 28px);
                        font-size: var(--auth-button-font-size, 16px);
                        font-weight: var(--auth-button-font-weight, 500);
                        font-family: var(--auth-button-font-family, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif);
                        cursor: pointer;
                        transition: all 0.2s ease;
                        display: inline-flex;
                        align-items: center;
                        justify-content: center;
                        gap: 8px;
                        text-decoration: none;
                        min-height: 48px;
                        min-width: fit-content;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                        white-space: nowrap;
                    }

                    button:hover:not(:disabled) {
                        background: var(--auth-button-hover-bg, #3367d6);
                        transform: translateY(-2px);
                        box-shadow: 0 4px 12px rgba(0,0,0,0.2);
                    }

                    button:active:not(:disabled) {
                        transform: translateY(0);
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    }

                    button:disabled {
                        opacity: 0.6;
                        cursor: not-allowed;
                        transform: none;
                    }

                    .brand {
                        font-family: "Josefin Sans", sans-serif;
                        font-weight: 700;
                        color: var(--auth-button-brand-color, #ff6b35);
                        text-shadow: 0 1px 2px rgba(0,0,0,0.1);
                    }

                    .loading {
                        width: 18px;
                        height: 18px;
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
                        --auth-button-brand-color: #ff8c5a;
                    }

                    .theme-outline {
                        --auth-button-bg: transparent;
                        --auth-button-color: #4285f4;
                        --auth-button-border: 2px solid #4285f4;
                        --auth-button-brand-color: #ff6b35;
                    }

                    .theme-outline:hover {
                        --auth-button-hover-bg: #4285f4;
                        --auth-button-color: white;
                    }
                </style>
                
                <button class="theme-${theme}" ${disabled ? "disabled" : ""}>
                    <span class="text">${this.getButtonText()}</span>
                </button>
            `;
        }

        addEventListeners() {
            const button = this.shadowRoot.querySelector("button");
            button.addEventListener("click", this.handleClick.bind(this));
        }

        async handleClick() {
            const button = this.shadowRoot.querySelector("button");
            if (button.disabled) return;

            const clientId = this.getAttribute("client-id");
            const type = this.getAttribute("type") || "login";

            if (!clientId) {
                console.error("auth-button: client-id attribute is required");
                return;
            }

            const originalWidth = button.offsetWidth;
            button.style.width = `${originalWidth}px`;

            this.setLoading(true);

            try {
                const scope = this.getAttribute("scope");
                const config = { clientId, scope };

                const result = type === "register"
                    ? await window.AuthSDK.register(config)
                    : await window.AuthSDK.login(config);

                this.dispatchEvent(new CustomEvent("auth-success", {
                    detail: result,
                    bubbles: true
                }));

            } catch (error) {
                this.dispatchEvent(new CustomEvent("auth-error", {
                    detail: error.message,
                    bubbles: true
                }));
            } finally {
                this.setLoading(false);
                button.style.width = "";
            }
        }

        setLoading(loading) {
            const button = this.shadowRoot.querySelector("button");
            const textSpan = this.shadowRoot.querySelector(".text");
            const originalText = this.getButtonText();

            if (loading) {
                button.disabled = true;
                textSpan.innerHTML = '<span class="loading"></span> Waiting...';
            } else {
                button.disabled = false;
                textSpan.innerHTML = originalText;
            }
        }
    }

    customElements.define("auth-button", AuthButton);
    window.AuthSDK = new AuthSDK();
})();