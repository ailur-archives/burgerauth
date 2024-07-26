if (localStorage.getItem("DONOTSHARE-secretkey") !== null || localStorage.getItem("DONOTSHARE-password") !== null) {
    window.location.replace("/app" + window.location.search)
    document.body.innerHTML = "Redirecting..."
    throw new Error();
}

let usernameBox = document.getElementById("usernameBox")
let passwordBox = document.getElementById("passwordBox")
let statusBox = document.getElementById("statusBox")
let signupButton = document.getElementById("signupButton")
let loginButton = document.getElementById("loginButton")
let inputContainer = document.getElementById("inputContainer")

function showElements(yesorno) {
    if (!yesorno) {
        inputContainer.classList.add("hidden")
        signupButton.classList.add("hidden")
        loginButton.classList.add("hidden")
    }
    else {
        inputContainer.classList.remove("hidden")
        signupButton.classList.remove("hidden")
        loginButton.classList.remove("hidden")
    }
}

complete = new Event("completed");
window.returnCode = undefined;
window.returnVar = undefined;

// This is for the WASM code to call when it's done. Do not remove it, even if it looks like it's never called.

function WASMComplete() {
    window.dispatchEvent(complete);
}

signupButton.addEventListener("click", () => {
    let username = usernameBox.value
    let password = passwordBox.value

    if (username === "") {
        statusBox.innerText = "A username is required!"
        return
    }

    if ((username).length > 20) {
        statusBox.innerText = "Username cannot be more than 20 characters!"
        return
    }
    if (password === "") {
        statusBox.innerText = "A password is required!"
        return
    }
    if ((password).length < 8) {
        statusBox.innerText = "8 or more characters are required!"
        return
    }

    async function hashpass(pass) {
        return await hashwasm.argon2id({
            password: pass,
            salt: new TextEncoder().encode("I munch Burgers!!"),
            parallelism: 1,
            iterations: 32,
            memorySize: 19264,
            hashLength: 32,
            outputType: "hex"
        })
    }

    showElements(false)
    statusBox.innerText = "Computing PoW Challenge... (this may take up to 5 minutes at worst, 3 seconds at best)"

    /*
     * Compiled version of:
     * hashcat-wasm (https://concord.hectabit.org/hectabit/hashcat-wasm)
     * (c) Arzumify
     * @license AGPL-3.0
     * Since this is my software, if you use it with proprietary servers, I will make sure you will walk across hot coals (just kidding, probably).
     * I'm not kidding about the license though.
     * I should stop including comments into JS and possibly minify this code. Oh, well.
    */

    window.resourceExtra = "I love Burgerauth!!"

    const go = new Go();
    WebAssembly.instantiateStreaming(fetch("/static/wasm/hashcat.wasm"), go.importObject).then((result) => {
        go.run(result.instance);
    })

    window.addEventListener("completed", async () => {
        if (window.returnCode === 1) {
            statusBox.innerText = "Please do not expose your computer to cosmic rays (an impossible logical event has occurred)."
            showElements(true)
            return
        } else if (window.returnCode === 2) {
            statusBox.innerText = "The PoW Challenge has failed. Please try again."
            showElements(true)
            return
        }

        statusBox.innerText = "Hashing password..."
        let hashedPass = await hashpass(password)
        statusBox.innerText = "Contacting server..."
        fetch("/api/signup", {
            method: "POST",
            body: JSON.stringify({
                username: username,
                password: hashedPass,
                stamp: window.returnVar
            }),
            headers: {
                "Content-Type": "application/json; charset=UTF-8"
            }
        })
            .then((response) => response)
            .then(async (response) => {
                let responseData = await response.json()
                console.log(responseData)

                if (response.status === 200) {
                    statusBox.innerText = "Setting up encryption keys..."
                    localStorage.setItem("DONOTSHARE-secretkey", responseData["key"])
                    localStorage.setItem("DONOTSHARE-password", await hashwasm.argon2id({
                        password: password,
                        salt: new TextEncoder().encode("I love Burgerauth!!"),
                        parallelism: 1,
                        iterations: 32,
                        memorySize: 19264,
                        hashLength: 32,
                        outputType: "hex"
                    }))

                    statusBox.innerText = "Welcome!"
                    await new Promise(r => setTimeout(r, 200))
                    window.location.href = "/app" + window.location.search
                } else if (response.status === 409) {
                    statusBox.innerText = "Username already taken!"
                    showElements(true)
                } else if (response.status === 500) {
                    statusBox.innerText = responseData["error"]
                    showElements(true)
                } else {
                    statusBox.innerText = "Something went wrong! (error code: " + responseData["error"] + ")"
                    showElements(true)
                }
            })
    })
})

document.getElementById("privacyButton").addEventListener("click", function(event) {
    event.preventDefault();

    const queryString = window.location.search;
    window.location.href = "/privacy" + queryString;
});

function toLogin() {
    window.location.href = "/login" + window.location.search;
}