# auth

This service is the central point of auth for sjallabong, with oauth2.

Clients are hardcoded for now.

```sh
git clone <this>
cd auth
cargo run
```

## Usage
There are convenience imports for a button to use.

### 1. Import and call the sign in button

```html
<link href="https://fonts.googleapis.com/css2?family=Josefin+Sans:wght@400;700&display=swap" rel="stylesheet">
<script src="https://auth.sjallabong.eu/sdk"></script>

<body>
    <auth-button 
        client-id="client-id"
        scope="openid profile">
        Sign in with Sjallabong
    </auth-button>

    <script>
        // on auth-success
        await fetch("/some-serverside-callback-handler", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code, state })
        });
    </script>
</body>
```

### 2. Exchange the token in backend

Use the code to get access and refresh tokens from the backend:
```js
const response = await fetch("https://auth.sjallabong.eu/token", {
    method: "POST",
    headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Basic " + btoa("client-id:client-secret")
    },
    body: new URLSearchParams({
        grant_type: "authorization_code",
        code: auth_code,
        redirect_uri: "https://auth.sjallabong.eu/success"
    })
});
```

## Scopes
- `openid` authentication
- `profile` username, avatar, etc
- `email`
- `pool` pool.sjallabong.eu stats
- `idle` todo
- `admin`