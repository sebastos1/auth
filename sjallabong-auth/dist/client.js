export default class OAuth2Client {
    constructor(bffUrl) {
        this.user = null;
        if (!bffUrl)
            throw new Error("BFF URL is required");
        this.bffUrl = bffUrl.replace(/\/$/, '');
        this.checkAuth();
    }
    getUser() {
        return this.user;
    }
    isAuthenticated() {
        return this.user !== null;
    }
    async checkAuth() {
        try {
            const response = await fetch(`${this.bffUrl}/check-session`, {
                credentials: 'include'
            });
            if (response.ok) {
                const data = await response.json();
                this.user = data.authenticated ? data.userInfo : null;
                return this.user;
            }
            this.user = null;
            return null;
        }
        catch (error) {
            this.user = null;
            return null;
        }
    }
    async login(usePopup = false) {
        if (usePopup) {
            const user = await this.loginPopup();
            this.user = user;
            return user;
        }
        else {
            window.location.href = `${this.bffUrl}/login`;
        }
    }
    loginPopup() {
        return new Promise((resolve, reject) => {
            const popup = window.open(`${this.bffUrl}/login?popup=true`, 'oauth-login', 'width=500,height=600,scrollbars=yes,resizable=yes');
            if (!popup)
                return reject(new Error("Failed to open popup"));
            const messageHandler = (event) => {
                // origin check
                if (!event.origin.startsWith(window.location.origin))
                    return;
                window.removeEventListener('message', messageHandler);
                clearInterval(checkClosed);
                clearTimeout(timeoutHandler);
                popup.close();
                if (event.data.type === 'oauth_success') {
                    resolve(event.data.userInfo || true);
                }
                else if (event.data.type === 'oauth_error') {
                    reject(new Error(event.data.error || 'Login failed'));
                }
                else {
                    reject(new Error('Invalid response from login'));
                }
            };
            const checkClosed = setInterval(() => {
                if (popup.closed) {
                    clearInterval(checkClosed);
                    clearTimeout(timeoutHandler);
                    window.removeEventListener('message', messageHandler);
                    reject(new Error('Login cancelled'));
                }
            }, 1000);
            const timeoutHandler = setTimeout(() => {
                if (!popup.closed) {
                    popup.close();
                    window.removeEventListener('message', messageHandler);
                    clearInterval(checkClosed);
                    reject(new Error('Login timeout'));
                }
            }, 300000);
            window.addEventListener('message', messageHandler);
        });
    }
    async logout() {
        try {
            await fetch(`${this.bffUrl}/logout`, {
                method: 'POST',
                credentials: 'include'
            });
        }
        catch (error) {
            console.log("Logout failed, still clearing local state:", error);
        }
        this.user = null;
    }
    async fetch(path, options = {}) {
        const url = path.startsWith('http') ? path : `${this.bffUrl}${path}`;
        const response = await fetch(url, {
            ...options,
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        });
        if (response.status === 401)
            await this.checkAuth();
        return response;
    }
}
/*

export interface AuthOptions {
    onSuccess?: (user: any) => void;
    onError?: (error: Error) => void;
}

export default class OAuth2Client {
    private config: OAuth2ClientConfig;

    constructor(config: OAuth2ClientConfig) {
        if (!config?.backendUrl) throw new Error("BFF URL is required");
        this.config = config;
    }

    renderButton(divId: string, options: AuthOptions = {}): void {
        const element = document.getElementById(divId);
        if (!element) throw new Error(`Element with id ${divId} not found`);

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

    async login(options: AuthOptions = {}): Promise<void> {
        try {
            const response = await fetch(`${this.config.backendUrl}/auth/login`);

            if (!response.ok) throw new Error(`Login failed: ${response.statusText}`);

            const { authUrl } = await response.json();
            const popup = this.openPopup(authUrl);
            this.setupHandlers(popup, options);

        } catch (error) {
            console.error("Auth error:", error);
            if (options.onError) {
                options.onError(error as Error);
            }
        }
    }

    // popup flow
    private openPopup(url: string): Window | null {
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

    private setupHandlers(popup: Window | null, options: AuthOptions): void {
        const messageHandler = (event: MessageEvent) => {
            const authServerOrigin = this.config.authServer ?
                new URL(this.config.authServer).origin :
                new URL(this.config.backendUrl).origin;

            if (event.origin !== authServerOrigin) return;

            if (event.data.type === "AUTH_SUCCESS") {
                this.handleAuthSuccess(options);
                window.removeEventListener("message", messageHandler);
                if (popup) popup.close();
            } else if (event.data.type === "AUTH_ERROR") {
                window.removeEventListener("message", messageHandler);
                if (popup) popup.close();
                if (options.onError) {
                    options.onError(new Error(event.data.error || "Authentication failed"));
                }
            }
        };

        window.addEventListener("message", messageHandler);
    }

    private async handleAuthSuccess(options: AuthOptions): Promise<void> {
        try {
            const user = await this.getUser();
            if (options.onSuccess && user) {
                options.onSuccess(user);
            }
        } catch (error) {
            console.error("Failed to get user info:", error);
            if (options.onError) {
                options.onError(error as Error);
            }
        }
    }

    // Get current user from BFF
    async getUser(): Promise<any> {
        const response = await fetch(`${this.config.backendUrl}/auth/user`, {
            credentials: 'include' // Include session cookies
        });

        if (!response.ok) {
            if (response.status === 401) return null; // Not authenticated
            throw new Error(`Failed to get user: ${response.statusText}`);
        }

        return await response.json();
    }

}
*/ 
