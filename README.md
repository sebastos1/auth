# auth

This service is the central point of auth for sjallabong, with oauth2, with pkce bff.

```sh
git clone https://gitlab.com/sjallabong/auth
cd auth
cargo run # port 3001
```

## Usage
### 1. Include the SDK and initialize
```html
<div id="loginBtn"></div>

<script src="https://auth.sjallabong.eu/sdk"></script>
<script>
    // Initialize the client
    Oauth2Client.initialize({
        clientId: 'your-client-id',
        authServer: 'https://auth.sjallabong.eu',
        scope: 'openid profile'
    });
    
    // Render the login button
    Oauth2Client.renderButton("loginBtn", {
        onSuccess: (tokens) => {
            console.log('Access token:', tokens.access_token);
            // Handle successful authentication
            localStorage.setItem('access_token', tokens.access_token);
        },
        onError: (error) => {
            console.error('Login failed:', error);
        }
    });
</script>
```

## Scopes
- `openid` authentication
- `profile` username, avatar, etc
- `email`

### todo
- `pool` pool.sjallabong.eu stats
- `idle`
- `admin`

