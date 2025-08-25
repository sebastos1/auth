export default class OAuth2Client {
    private bffUrl;
    private user;
    constructor(bffUrl: string);
    getUser(): any;
    isAuthenticated(): boolean;
    checkAuth(): Promise<any>;
    login(usePopup?: boolean): Promise<any>;
    private loginPopup;
    logout(): Promise<void>;
    fetch(path: string, options?: RequestInit): Promise<Response>;
}
