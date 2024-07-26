async function main() {
    try {
        const urlParams = new URLSearchParams(window.location.search);
        const token = urlParams.get('token');
        if (!token) {
            document.getElementById("errors").innerText = "No token was provided. Redirecting to dashboard...";
            setTimeout(() => {
                window.location.replace("/dashboard");
            }, 3000);
        } else {
            const response = await fetch("/api/aeskeyshare", {
                method: "POST",
                body: JSON.stringify({
                    access_token: token
                }),
                headers: {
                    "Content-Type": "application/json; charset=UTF-8"
                }
            });
            if (response.status === 200) {
                let responseData = await response.json();
                const publicKeyParam = urlParams.get('pubkey');
                if (!publicKeyParam) {
                    document.getElementById("errors").innerText = "The website you were visiting has not provided a public key. Encryption cannot proceed. Redirecting to dashboard...";
                    setTimeout(() => {
                        window.location.replace("/dashboard");
                    }, 3000);
                } else {
                    const publicKeyBytes = atob(publicKeyParam.replace(/_/g, '/').replace(/~/g, '+'));
                    const publicKeyBuffer = new Uint8Array(publicKeyBytes.length);
                    for (let i = 0; i < publicKeyBytes.length; i++) {
                        publicKeyBuffer[i] = publicKeyBytes.charCodeAt(i);
                    }
                    let publicKey;
                    try {
                        publicKey = await window.crypto.subtle.importKey(
                            "spki",
                            publicKeyBuffer,
                            {
                                name: "RSA-OAEP",
                                hash: {name: "SHA-512"}
                            },
                            true,
                            ["encrypt"]
                        );
                    } catch (error) {
                        console.error('Error:', error.message);
                        document.getElementById("errors").innerText = "The public key provided by the website is invalid. Encryption cannot proceed. Redirecting to dashboard...";
                        setTimeout(() => {
                            window.location.replace("/dashboard");
                        }, 3000);
                        return
                    }
                    document.getElementById("errors").innerText = "Generating encryption keys...";
                    const message = await hashwasm.argon2id({
                        password: localStorage.getItem("DONOTSHARE-password") + responseData["appId"],
                        salt: new TextEncoder().encode("Burgers are yum!"),
                        parallelism: 1,
                        iterations: 32,
                        memorySize: 19264,
                        hashLength: 32,
                        outputType: "hex"
                    });
                    document.getElementById("errors").innerText = "Encrypting message...";
                    const encryptedMessageBuffer = await window.crypto.subtle.encrypt(
                        {
                            name: "RSA-OAEP"
                        },
                        publicKey,
                        new TextEncoder().encode(message)
                    );
                    const encodedMessage = btoa(String.fromCharCode.apply(null, new Uint8Array(encryptedMessageBuffer))).replace(/\+/g, '~').replace(/\//g, '_').replace(/=+$/, '');
                    window.location.replace(responseData["keyShareUri"] + "/?encoded=" + encodedMessage)
                }
            } else if (response.status === 401) {
                const responseData = await response.json();
                document.getElementById("errors").innerText = "The token provided is invalid: " + responseData["error"] + " Redirecting to dashboard...";
                setTimeout(() => {
                    window.location.replace("/dashboard");
                }, 3000);
            } else if (response.status === 500) {
                const responseData = await response.json();
                document.getElementById("errors").innerText = responseData["error"];
                setTimeout(() => {
                    window.location.replace("/dashboard");
                }, 3000);
            } else if (response.status === 403) {
                document.getElementById("errors").innerText = "The token provided has expired. Redirecting to dashboard...";
                setTimeout(() => {
                    window.location.replace("/dashboard");
                }, 3000);
            } else {
                const responseData = await response.json();
                document.getElementById("errors").innerText = "An unknown error occurred: " + responseData["error"] + " Redirecting to dashboard...";
                setTimeout(() => {
                    window.location.replace("/dashboard");
                }, 3000);
            }
        }
    } catch (error) {
        console.error('Error:', error.message);
        document.getElementById("errors").innerText = "An error occurred and was logged to the console. Redirecting to dashboard...";
        setTimeout(() => {
            window.location.replace("/dashboard");
        }, 3000);
    }
}

window.onload = main;