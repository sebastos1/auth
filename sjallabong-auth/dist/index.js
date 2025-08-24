export default class OAuth2Server {
    constructor(config) {
        this.sessions = new Map();
        if (!config?.clientId)
            throw new Error("Client ID is required");
        if (!config?.authServer)
            throw new Error("Auth server URL is required");
        this.config = {
            clientId: config.clientId,
            authServer: config.authServer,
            scope: config.scope || "openid profile",
            redirectUri: config.redirectUri || `${config.authServer}/success`,
            successUri: config.successUri || "/",
            services: config.services || {},
        };
    }
    generateCode(length) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return btoa(String.fromCharCode(...array)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
    async sha256(text) {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        const hash = await crypto.subtle.digest('SHA-256', data);
        return btoa(String.fromCharCode(...new Uint8Array(hash))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
    async login() {
        try {
            const codeVerifier = this.generateCode(32);
            const codeChallenge = await this.sha256(codeVerifier);
            const state = this.generateCode(16); // 16-32 recommended
            // todo: store this somewhere, and clean old ones
            const sessionId = this.generateCode(32);
            this.sessions.set(sessionId, {
                accessToken: '',
                codeVerifier,
                state,
                expiresAt: Date.now() + 600000
            });
            const params = new URLSearchParams({
                client_id: this.config.clientId,
                redirect_uri: this.config.redirectUri,
                scope: this.config.scope,
                state: state,
                code_challenge: codeChallenge,
                code_challenge_method: "S256",
                response_type: "code"
            });
            const authUrl = `${this.config.authServer}/authorize?${params}`;
            return new Response(null, {
                status: 302,
                headers: {
                    'Location': authUrl,
                    'Set-Cookie': `session_id=${sessionId}; HttpOnly; Secure; SameSite=Strict; Path=/;`
                }
            });
        }
        catch (error) {
            return new Response(JSON.stringify({ error: 'Login initiation failed' }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }
    async getTokens(code, codeVerifier) {
        const response = await fetch(`${this.config.authServer}/token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: this.config.clientId,
                code,
                redirect_uri: this.config.redirectUri,
                code_verifier: codeVerifier
            })
        });
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Token exchange failed: ${errorText}`);
        }
        return await response.json();
    }
    decodeIdToken(idToken) {
        const payload = idToken.split('.')[1];
        const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
        return JSON.parse(decoded);
    }
    getSessionId(request) {
        const cookies = request.headers.get('cookie');
        if (!cookies)
            return null;
        const sessionMatch = cookies.match(/session_id=([^;]+)/);
        if (!sessionMatch)
            return null;
        return sessionMatch[1];
    }
    // todo store better
    getSession(sessionId) {
        return this.sessions.get(sessionId) || null;
    }
    async callback(request) {
        try {
            const url = new URL(request.url);
            const auth_code = url.searchParams.get('code');
            const state = url.searchParams.get('state');
            const error = url.searchParams.get('error');
            if (error)
                return new Response(null, { status: 302, headers: { 'Location': `${this.config.redirectUri}?error=${error}` } });
            if (!auth_code || !state)
                return new Response('Missing authorization code or state', { status: 400 });
            const sessionId = this.getSessionId(request);
            if (!sessionId)
                return new Response('Invalid session', { status: 400 });
            const session = this.getSession(sessionId);
            if (!session)
                return new Response('Invalid session', { status: 400 });
            if (session.state !== state)
                return new Response('State mismatch', { status: 400 });
            if (!session.codeVerifier)
                return new Response('Missing code verifier', { status: 400 });
            // authorization code -> tokens
            const tokens = await this.getTokens(auth_code, session.codeVerifier);
            session.accessToken = tokens.access_token;
            session.refreshToken = tokens.refresh_token;
            session.expiresAt = Date.now() + (tokens.expires_in * 1000);
            if (tokens.id_token) {
                session.userInfo = this.decodeIdToken(tokens.id_token);
            }
            delete session.codeVerifier;
            delete session.state;
            return new Response(null, {
                status: 302,
                headers: {
                    'Location': this.config.successUri,
                    'Set-Cookie': `session_id=${sessionId}; HttpOnly; Secure; SameSite=Strict; Path=/;`
                }
            });
        }
        catch (error) {
            console.error('Callback error:', error);
            return new Response(JSON.stringify({ error: 'Authentication failed' }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }
    async logout() {
        return new Response(null, {
            status: 302,
            headers: {
                'Location': this.config.successUri,
                'Set-Cookie': `session_id=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`
            }
        });
    }
    async refresh(session) {
        const response = await fetch(`${this.config.authServer}/token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                grant_type: 'refresh_token',
                client_id: this.config.clientId,
                refresh_token: session.refreshToken
            })
        });
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Refresh token exchange failed: ${response.status} - ${errorText}`);
        }
        const tokens = await response.json();
        session.accessToken = tokens.access_token;
        session.refreshToken = tokens.refresh_token;
        session.expiresAt = Date.now() + (tokens.expires_in * 1000);
    }
    // bff proxy
    async fetchApi(request) {
        const sessionId = this.getSessionId(request);
        if (!sessionId)
            return new Response('No session', { status: 401 });
        const session = this.getSession(sessionId);
        if (!session?.accessToken)
            return new Response('Unauthorized', { status: 401 });
        // try initial request with access
        let response = await this.makeRequest(request, session.accessToken);
        // if 401 and we have a refresh, try once
        if (response.status === 401 && session.refreshToken) {
            try {
                await this.refresh(session);
                response = await this.makeRequest(request, session.accessToken);
            }
            catch (error) {
                return new Response('Unauthorized', { status: 401 });
            }
        }
        return response;
    }
    async makeRequest(request, accessToken) {
        const allowedMethods = ['GET', 'POST', 'PUT', 'DELETE'];
        if (!allowedMethods.includes(request.method))
            return new Response('Method not allowed', { status: 405 });
        const url = new URL(request.url);
        const servicePath = Object.keys(this.config.services).find(path => url.pathname.startsWith(path));
        if (!servicePath)
            return new Response('Service not found', { status: 404 });
        // path traversal
        const relativePath = url.pathname.slice(servicePath.length);
        if (relativePath.includes('..') || relativePath.includes('//'))
            return new Response('Invalid path', { status: 400 });
        const baseUrl = this.config.services[servicePath].replace(/\/$/, '');
        const targetUrl = `${baseUrl}${relativePath}`;
        const proxyHeaders = new Headers(request.headers);
        proxyHeaders.delete('cookie');
        proxyHeaders.set('Authorization', `Bearer ${accessToken}`);
        return fetch(targetUrl + url.search, {
            method: request.method,
            headers: proxyHeaders,
            body: request.body
        });
    }
    // authenticated: bool, userInfo: object|null
    async checkSession(request) {
        const sessionId = this.getSessionId(request);
        const session = sessionId ? this.getSession(sessionId) : null;
        if (session?.accessToken && session.expiresAt > Date.now()) {
            return new Response(JSON.stringify({
                authenticated: true,
                userInfo: session.userInfo
            }), {
                headers: { 'Content-Type': 'application/json' }
            });
        }
        return new Response(JSON.stringify({ authenticated: false }), {
            headers: { 'Content-Type': 'application/json' }
        });
    }
}
