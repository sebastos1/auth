// cors header
// todo this bad boy
export default class OAuth2Client {
    constructor(config) {
        if (!config?.backendUrl) {
            throw new Error("BFF base URL is required");
        }
        this.config = config;
    }
    renderButton(divId, options = {}) {
        const element = document.getElementById(divId);
        if (!element)
            throw new Error(`Element with id ${divId} not found`);
        element.innerHTML = `
            <button style="
                background: #23262aff;
                color: #f8f9fa;
                border: none;
                border-radius: 4px;
                padding: 14px 28px;
                font-size: 16px;
                cursor: pointer;
                font-family: system-ui, sans-serif;
            ">Log in</button>
        `;
        const button = element.querySelector("button");
        if (button) {
            button.addEventListener("click", () => this.login(options));
        }
    }
    async login(options = {}) {
        try {
            const response = await fetch(`${this.config.backendUrl}/auth/login`);
            if (!response.ok)
                throw new Error(`Login failed: ${response.statusText}`);
            const { authUrl } = await response.json();
            const popup = this.openPopup(authUrl);
            this.setupHandlers(popup, options);
        }
        catch (error) {
            console.error("Auth error:", error);
            if (options.onError) {
                options.onError(error);
            }
        }
    }
    // popup flow
    openPopup(url) {
        const width = 500;
        const height = 650;
        const left = Math.round((window.screen.width / 2) - (width / 2));
        const top = Math.round((window.screen.height / 2) - (height / 2));
        const features = [
            `width=${width}`,
            `height=${height}`,
            `left=${left}`,
            `top=${top}`,
            "resizable=no",
            "status=no",
            "toolbar=no",
            "menubar=no",
            "location=no"
        ].join(",");
        return window.open(url, "oauth-popup", features);
    }
    setupHandlers(popup, options) {
        const messageHandler = (event) => {
            const authServerOrigin = this.config.authServer ?
                new URL(this.config.authServer).origin :
                new URL(this.config.backendUrl).origin;
            if (event.origin !== authServerOrigin)
                return;
            if (event.data.type === "AUTH_SUCCESS") {
                this.handleAuthSuccess(options);
                window.removeEventListener("message", messageHandler);
                if (popup)
                    popup.close();
            }
            else if (event.data.type === "AUTH_ERROR") {
                window.removeEventListener("message", messageHandler);
                if (popup)
                    popup.close();
                if (options.onError) {
                    options.onError(new Error(event.data.error || "Authentication failed"));
                }
            }
        };
        window.addEventListener("message", messageHandler);
    }
    async handleAuthSuccess(options) {
        try {
            const user = await this.getUser();
            if (options.onSuccess && user) {
                options.onSuccess(user);
            }
        }
        catch (error) {
            console.error("Failed to get user info:", error);
            if (options.onError) {
                options.onError(error);
            }
        }
    }
    // Get current user from BFF
    async getUser() {
        const response = await fetch(`${this.config.backendUrl}/auth/user`, {
            credentials: 'include' // Include session cookies
        });
        if (!response.ok) {
            if (response.status === 401)
                return null; // Not authenticated
            throw new Error(`Failed to get user: ${response.statusText}`);
        }
        return await response.json();
    }
}
