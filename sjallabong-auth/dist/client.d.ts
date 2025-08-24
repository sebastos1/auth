export interface OAuth2ClientConfig {
    backendUrl: string;
    authServer?: string;
}
export interface AuthOptions {
    onSuccess?: (user: any) => void;
    onError?: (error: Error) => void;
}
export default class OAuth2Client {
    private config;
    constructor(config: OAuth2ClientConfig);
    renderButton(divId: string, options?: AuthOptions): void;
    login(options?: AuthOptions): Promise<void>;
    private openPopup;
    private setupHandlers;
    private handleAuthSuccess;
    getUser(): Promise<any>;
}
