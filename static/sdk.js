(function () {
    const AUTH_SERVER = window.AUTH_SERVER_URL || 'http://localhost:3001';

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
                    response_type: 'code',
                    client_id: config.clientId,
                    redirect_uri: `${AUTH_SERVER}/success`,
                    scope: config.scope || 'openid profile',
                    state: state
                });

                const authUrl = `${AUTH_SERVER}/authorize?${params}`;
                this.popup = this.openPopup(authUrl);

                const messageHandler = (event) => {
                    if (event.origin !== AUTH_SERVER) return;

                    if (event.data.type === 'AUTH_SUCCESS') {
                        window.removeEventListener('message', messageHandler);
                        this.popup.close();
                        resolve({ code: event.data.code, state: event.data.state });
                    }

                    if (event.data.type === 'AUTH_ERROR') {
                        window.removeEventListener('message', messageHandler);
                        this.popup.close();
                        reject(new Error(event.data.error));
                    }
                };

                window.addEventListener('message', messageHandler);

                const checkClosed = setInterval(() => {
                    if (this.popup.closed) {
                        clearInterval(checkClosed);
                        window.removeEventListener('message', messageHandler);
                        reject(new Error('Login cancelled'));
                    }
                }, 1000);
            });
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
                'scrollbars=yes',
                'resizable=yes',
                'status=no',
                'toolbar=no',
                'menubar=no',
                'location=no'
            ].join(',');

            return window.open(url, 'auth-login', features);
        }

        generateState() {
            return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
        }
    }

    window.AuthSDK = new AuthSDK();
})();