export interface Config {
    clientId: string;
    authServer: string;
    scope?: string;
    redirectUri?: string;
    successUri?: string;
    services: Record<string, string>;
}
export default class OAuth2Server {
    private config;
    private sessions;
    constructor(config: Config);
    private generateCode;
    private sha256;
    login(): Promise<Response>;
    private getTokens;
    private decodeIdToken;
    private getSessionId;
    private getSession;
    callback(request: Request): Promise<Response>;
    logout(): Promise<Response>;
    private refresh;
    fetchApi(request: Request): Promise<Response>;
    private makeRequest;
    checkSession(request: Request): Promise<Response>;
}
