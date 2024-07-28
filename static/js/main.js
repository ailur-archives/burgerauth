let client_id, redirect_uri, response_type, state, code, codemethod, secret_key, nonce;

if (localStorage.getItem("DONOTSHARE-secretkey") === null) {
    throw new Error();
}

document.addEventListener("DOMContentLoaded", function() {
   checkNetwork().then((result) => {
       if (result) {
           const urlParams = new URLSearchParams(window.location.search);
           const statusBox = document.getElementById("statusBox");

           if (urlParams.has('client_id')) {
               client_id = urlParams.get('client_id')
               let name = document.getElementById("passthrough").innerText;
               redirect_uri = urlParams.get('redirect_uri');
               statusBox.textContent = "Would you like to allow " + name + " to access your user information? You will be redirected to " + redirect_uri + " after you make your decision.";
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

           secret_key = localStorage.getItem("DONOTSHARE-secretkey");
       }
   })
});

function deny() {
    window.location.replace("/api/auth?client_id=" + client_id + "&redirect_uri=" + redirect_uri + "&code_challenge_method=" + codemethod + "&code_challenge=" + code + "&state=" + state + "&nonce=" + nonce + "&deny=true");
}

function oauth() {
    const now = new Date();
    const expireTime = now.getTime() + (21 * 1000);
    let expires = new Date(expireTime).toUTCString();
    if (navigator.cookieEnabled) {
        document.cookie = "session=" + secret_key + "; expires=" + expires + "; path=/";
        window.location.replace("/api/auth?client_id=" + client_id + "&redirect_uri=" + redirect_uri + "&code_challenge_method=" + codemethod + "&code_challenge=" + code + "&state=" + state + "&nonce=" + nonce + "&deny=false");
    } else {
        document.getElementById("statusBox").textContent = "Warning! Because cookies are disabled, your access token is sent directly in the URL. This is less secure than using cookies, but you chose this path!";
        setTimeout(() => {
            window.location.replace("/api/auth?client_id=" + client_id + "&redirect_uri=" + redirect_uri + "&code_challenge_method=" + codemethod + "&code_challenge=" + code + "&state=" + state + "&nonce=" + nonce + "&deny=false&session=" + secret_key);
        }, 200);
    }
}

async function checkNetwork() {
    let loggedIn = await fetch("/api/secretkeyloggedin", {
        method: "POST",
        body: JSON.stringify({
            secretKey: localStorage.getItem("DONOTSHARE-secretkey")
        }),
        headers: {
            "Content-Type": "application/json; charset=UTF-8"
        }
    })
    if (loggedIn.status === 200) {
        return true
    } else {
        localStorage.removeItem("DONOTSHARE-secretkey");
        localStorage.removeItem("DONOTSHARE-password");
        window.location.replace("/login" + window.location.search);
        return false
    }
}
