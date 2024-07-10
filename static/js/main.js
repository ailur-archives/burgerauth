let client_id, redirect_uri, response_type, state, code, codemethod, secret_key, expires, nonce;

if (localStorage.getItem("DONOTSHARE-secretkey") === null) {
    window.location.replace("/login" + window.location.search)
    document.body.innerHTML = "Redirecting..."
    throw new Error();
}

document.addEventListener("DOMContentLoaded", function() {
    const urlParams = new URLSearchParams(window.location.search);
    const statusBox = document.getElementById("statusBox");

    // Get URL parameters
    if (urlParams.has('client_id')) {
        client_id = urlParams.get('client_id')
        let name = document.getElementById("passthrough").innerText;
        statusBox.textContent = "Would you like to allow " + name + " to access your user information?";
        redirect_uri = urlParams.get('redirect_uri');
        response_type = urlParams.get('response_type');
    } else {
        window.location.replace("/dashboard");
        document.body.innerHTML = "Redirecting..."
        throw new Error();
    }

    state = urlParams.has('state') ? urlParams.get('state') : "none";

    if (urlParams.has('code_challenge')) {
        code = urlParams.get('code_challenge');
        codemethod = urlParams.get('code_challenge_method');
    } else {
        code = "none";
        codemethod = "none";
    }

    if (urlParams.has('nonce')) {
        nonce = urlParams.get('nonce');
    } else {
        nonce = "none";
    }

    // Get DONOTSHARE-secretkey from localStorage
    secret_key = localStorage.getItem("DONOTSHARE-secretkey");
    const now = new Date();
    const expireTime = now.getTime() + (21 * 1000); // 21 seconds from now
    expires = new Date(expireTime).toUTCString();
});

function deny() {
    document.cookie = "key=" + secret_key + "; expires=" + expires + "; path=/; SameSite=Strict";
    // Redirect to the redirect_uri so that an open redirect is not possible
    window.location.replace("/api/auth?client_id=" + client_id + "&redirect_uri=" + redirect_uri + "&code_challenge_method=" + codemethod + "&code_challenge=" + code + "&state=" + state + "&nonce=" + nonce + "&deny=true");
}

function oauth() {
    document.cookie = "key=" + secret_key + "; expires=" + expires + "; path=/; SameSite=Strict";
    window.location.replace("/api/auth?client_id=" + client_id + "&redirect_uri=" + redirect_uri + "&code_challenge_method=" + codemethod + "&code_challenge=" + code + "&state=" + state + "&nonce=" + nonce + "&deny=false");
}