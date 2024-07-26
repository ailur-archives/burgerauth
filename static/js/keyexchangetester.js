function saveArrayBufferToLocalStorage(key, buffer) {
    const base64String = arrayBufferToBase64(buffer);
    localStorage.setItem(key, base64String);
}

function getArrayBufferFromLocalStorage(key) {
    const base64String = localStorage.getItem(key);
    if (base64String) {
        return base64ToArrayBuffer(base64String);
    }
    return null;
}

function arrayBufferToBase64(buffer) {
    const uint8Array = new Uint8Array(buffer);
    return btoa(String.fromCharCode.apply(null, uint8Array)).replace(/\+/g, '~').replace(/\//g, '_').replace(/=+$/, '');
}

function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64.replace(/_/g, '/').replace(/~/g, '+'));
    const length = binaryString.length;
    const buffer = new ArrayBuffer(length);
    const uint8Array = new Uint8Array(buffer);
    for (let i = 0; i < length; i++) {
        uint8Array[i] = binaryString.charCodeAt(i);
    }
    return buffer;
}

function generateKeyPair() {
    return window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 4096,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: {name: "SHA-512"}
        },
        true,
        ["encrypt", "decrypt"]
    );
}

async function main() {
    const urlParams = new URLSearchParams(window.location.search);
    const encodedData = urlParams.get('encoded');
    const doNothing = urlParams.get('donothing');
    let keyShareUri = "https://auth.hectabit.org/aeskeyshare"
    if (localStorage.getItem("keyShareUri") !== null) {
        keyShareUri = localStorage.getItem("keyShareUri")
    }
    if (localStorage.getItem("referrer") === null) {
        return
    }
    if (doNothing !== "true") {
        if (encodedData) {
            const decodedData = base64ToArrayBuffer(encodedData);
            const decryptedData = window.crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP"
                },
                await crypto.subtle.importKey("pkcs8", getArrayBufferFromLocalStorage("key"), {
                    name: "RSA-OAEP",
                    hash: {name: "SHA-512"}
                }, true, ["decrypt"]),
                decodedData
            );
            localStorage.setItem("DONOTSHARE-EXCHANGED-KEY", new TextDecoder().decode(await decryptedData));
            window.location.replace(localStorage.getItem("referrer"))
        } else {
            let keyPair = await generateKeyPair();
            saveArrayBufferToLocalStorage("key", await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));
            window.location.replace(keyShareUri + "?pubkey=" + btoa(String.fromCharCode.apply(null, new Uint8Array(await crypto.subtle.exportKey("spki", keyPair.publicKey)))).replace(/\+/g, '~').replace(/\//g, '_').replace(/=+$/, '') + "&token=" + localStorage.getItem("BURGERAUTH-RDIR-TOKEN"));
        }
    }
}

window.onload = main;