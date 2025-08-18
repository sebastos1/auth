class Oauth2Client {
    static config = null;

    static initialize(config) {
        if (!config || !config.clientId) {
            throw new Error("Client ID is required for OAuth2Client initialization.");
        }

        // just being explicit
        this.config = {
            clientId: config.clientId,
            authServer: config.authServer || "https://auth.sjallabong.eu",
            scope: config.scope || "openid profile",
            redirectUri: config.redirectUri || `${config.authServer}/success`,
        }
    }

    static getConfig() {
        if (!this.config) {
            throw new Error("OAuth2Client is not initialized. Call initialize() first.");
        }
        return this.config;
    }

    // pkce
    static generateCodeVerifier() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    static async generateCodeChallenge(codeVerifier) {
        const encoder = new TextEncoder();
        const data = encoder.encode(codeVerifier);
        const digest = await crypto.subtle.digest('SHA-256', data);
        return btoa(String.fromCharCode(...new Uint8Array(digest)))
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    static generateState() {
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    // button
    static renderButton(divId, options = {}) {
        let element = document.getElementById(divId);

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
        button.addEventListener("click", () => { Oauth2Client.handleClick(options) });;
    }

    static async handleClick(options = {}) {
        try {
            const config = Oauth2Client.getConfig();
            const codeVerifier = Oauth2Client.generateCodeVerifier();
            const codeChallenge = await Oauth2Client.generateCodeChallenge(codeVerifier);
            const state = Oauth2Client.generateState();

            sessionStorage.setItem('oauth_code_verifier', codeVerifier);
            sessionStorage.setItem('oauth_state', state);

            const params = new URLSearchParams({
                client_id: config.clientId,
                redirect_uri: config.redirectUri,
                scope: config.scope,
                state: state,
                code_challenge: codeChallenge,
                code_challenge_method: 'S256'
            });

            const authUrl = `${config.authServer}/authorize?${params}`;
            const popup = Oauth2Client.openPopup(authUrl);
            Oauth2Client.setupHandlers(popup, options);
        } catch (error) {
            console.error('Auth error:', error);
        }
    }

    static openPopup(url) {
        const width = 500;
        const height = 650;
        const left = Math.round((screen.width / 2) - (width / 2));
        const top = Math.round((screen.height / 2) - (height / 2));

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

    static setupHandlers(popup, options) {
        const config = Oauth2Client.getConfig();

        // listens for messages from /success
        const messageHandler = (event) => {
            if (event.origin !== config.authServer) return;
            if (event.data.type === 'AUTH_SUCCESS') {
                Oauth2Client.handleCallback(event.data, options);
                window.removeEventListener('message', messageHandler);
                if (popup) popup.close();
            } else if (event.data.type === 'AUTH_ERROR') {
                window.removeEventListener('message', messageHandler);
                if (popup) popup.close();
                if (options.onError) {
                    options.onError(new Error(event.data.error || 'Authentication failed'));
                }
            }
        };

        window.addEventListener('message', messageHandler);
    }

    static async handleCallback(data, options) {
        try {
            const storedState = sessionStorage.getItem('oauth_state');
            if (data.state !== storedState) throw new Error('Invalid state');

            // trade code for access token
            const tokens = await Oauth2Client.exchangeCodeForTokens(data.code);

            // clean old ones
            sessionStorage.removeItem('oauth_code_verifier');
            sessionStorage.removeItem('oauth_state');

            // call the client's handlers
            if (options.onSuccess) {
                options.onSuccess(tokens);
            }
        } catch (error) {
            console.error('OAuth callback error:', error);
            if (options.onError) {
                options.onError(error);
            }
        }
    }

    static async exchangeCodeForTokens(code) {
        const config = Oauth2Client.getConfig();
        const codeVerifier = sessionStorage.getItem('oauth_code_verifier');

        const response = await fetch(`${config.authServer}/token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: config.clientId,
                code,
                redirect_uri: config.redirectUri,
                code_verifier: codeVerifier
            })
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Token exchange failed: ${errorText}`);
        }

        return await response.json();
    }
}

window.Oauth2Client = Oauth2Client;