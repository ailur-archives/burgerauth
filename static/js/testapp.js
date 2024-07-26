let clientId
const redirectUri = window.location.href.replace(window.location.search, "")
let authorizationEndpoint
let tokenEndpoint
let userinfoEndpoint

function generateCodeVerifier() {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
    const length = 128;
    return Array.from(crypto.getRandomValues(new Uint8Array(length)))
        .map((x) => charset[x % charset.length])
        .join("");
}

async function createCodeChallenge(codeVerifier) {
    const buffer = new TextEncoder().encode(codeVerifier);
    const hashArrayBuffer = await crypto.subtle.digest('SHA-256', buffer);
    return btoa(String.fromCharCode(...new Uint8Array(hashArrayBuffer)))
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
}

function authorize() {
    const codeVerifier = generateCodeVerifier();
    localStorage.setItem('codeVerifier', codeVerifier); // Store code verifier
    createCodeChallenge(codeVerifier)
        .then((codeChallenge) => {
            window.location.href = `${authorizationEndpoint}?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&code_challenge=${codeChallenge}&code_challenge_method=S256`;
        })
        .catch((error) => {
            console.error('Error generating code challenge:', error);
        });
}

async function exchangeCodeForToken(code) {
    const codeVerifier = localStorage.getItem('codeVerifier'); // Retrieve code verifier
    const formData = new URLSearchParams();
    formData.append('client_id', String(clientId));
    formData.append('code', String(code));
    formData.append('redirect_uri', String(redirectUri));
    formData.append('grant_type', 'authorization_code');
    formData.append('code_verifier', String(codeVerifier));

    let response
    if (localStorage.getItem('noPost') !== "true") {
        response = await fetch(tokenEndpoint, {
            method: 'POST',
            headers: {
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: formData
        });
    } else {
        return
    }

    const data = await response.json();
    const accessToken = data["access_token"];
    const idToken = data["id_token"];

    fetch(userinfoEndpoint, {
        headers: {
            "Authorization": `Bearer ${idToken}`
        }
    })
        .then((response) => {
            async function doStuff() {
                if (response.status === 200) {
                    const userinfoData = await response.json();
                    console.log(accessToken, idToken)
                    console.log("User:", userinfoData.name)
                    console.log("Sub:", userinfoData.sub);
                    document.getElementById("text").innerText = "Authenticated, " + userinfoData.name + ", beginning AES Key Share...";
                    localStorage.setItem("user", userinfoData.name)
                    localStorage.setItem("sub", userinfoData.sub)
                    localStorage.setItem("keyShareUri", document.getElementById("server_uri").innerText + "/aeskeyshare");
                    localStorage.setItem("referrer", redirectUri);
                    localStorage.setItem("BURGERAUTH-RDIR-TOKEN", accessToken);
                    window.location.replace("/keyexchangetester");
                } else {
                    document.getElementById("text").innerText = "Authentication failed"
                }
            }
            doStuff()
        });
}

async function main() {
    clientId = document.getElementById("client_id").innerText;
    authorizationEndpoint = document.getElementById("server_uri").innerText + "/login";
    tokenEndpoint = document.getElementById("server_uri").innerText + "/api/tokenauth";
    userinfoEndpoint = document.getElementById("server_uri").innerText + "/userinfo";

    console.log({
        clientId,
        redirectUri,
        authorizationEndpoint,
        tokenEndpoint,
        userinfoEndpoint
    });

    if (localStorage.getItem("user") !== null) {
        document.getElementById("text").innerText = "Welcome back, " + localStorage.getItem("user")
    }

    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('code')) {
        await exchangeCodeForToken(urlParams.get('code'));
    } else if (urlParams.get('error')) {
        if (urlParams.get('error') === "access_denied") {
            document.getElementById("text").innerText = "Access denied"
        } else {
            document.getElementById("text").innerText = "Authentication failed (error code: " + urlParams.get('error') + ")"
        }
    } else if (localStorage.getItem("DONOTSHARE-EXCHANGED-KEY") !== null) {
        document.getElementById("text").style.overflowWrap = "break-word"
        document.getElementById("text").innerText = "AES Key Share complete! Authenticated as " + localStorage.getItem("user") + ", key is " + localStorage.getItem("DONOTSHARE-EXCHANGED-KEY") + "."
        localStorage.removeItem("referrer")
        localStorage.removeItem("keyShareUri")
        localStorage.removeItem("key")
        localStorage.removeItem("BURGERAUTH-RDIR-TOKEN")
        localStorage.removeItem("codeVerifier")
        localStorage.removeItem("sub")
        localStorage.removeItem("DONOTSHARE-EXCHANGED-KEY")
        localStorage.removeItem("user")
    }
}

document.addEventListener('DOMContentLoaded', main);