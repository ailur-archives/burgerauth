if (localStorage.getItem("DONOTSHARE-secretkey") !== null) {
    window.location.replace("/app" + window.location.search)
    document.body.innerHTML = "Redirecting..."
    throw new Error();
}
if (localStorage.getItem("DONOTSHARE-password") !== null) {
    window.location.replace("/app" + window.location.search)
    document.body.innerHTML = "Redirecting..."
    throw new Error();
}

let usernameBox = document.getElementById("usernameBox")
let passwordBox = document.getElementById("passwordBox")
let statusBox = document.getElementById("statusBox")
let nextButton = document.getElementById("nextButton")
let signupButton = document.getElementById("signupButton")
let inputNameBox = document.getElementById("inputNameBox")
let backButton = document.getElementById("backButton")
let inputContainer = document.getElementById("inputContainer")

usernameBox.classList.remove("hidden")
inputNameBox.innerText = "Username:"

let currentInputType = 0

function showInput(inputType) {
    if (inputType === 0) {
        inputContainer.classList.remove("hidden")
        usernameBox.classList.remove("hidden")
        signupButton.classList.remove("hidden")
        passwordBox.classList.add("hidden")
        backButton.classList.add("hidden")
        inputNameBox.innerText = "Username:"
        let serviceName
        fetch("/api/servicename")
            .then((response) => response.json())
            .then((response) => {
                serviceName = response["name"]
                statusBox.innerText = "Login to your " + serviceName + " account!"
                currentInputType = 0
            })
    } else if (inputType === 1) {
        inputContainer.classList.remove("hidden")
        signupButton.classList.add("hidden")
        usernameBox.classList.add("hidden")
        passwordBox.classList.remove("hidden")
        backButton.classList.remove("hidden")
        inputNameBox.innerText = "Password:"
        currentInputType = 1
    } else if (inputType === 2) {
        signupButton.classList.add("hidden")
        nextButton.classList.add("hidden")
        backButton.classList.add("hidden")
        inputContainer.classList.add("hidden")
        inputNameBox.classList.add("hidden")
        currentInputType = 2
    }
}

function showElements(yesorno) {
    if (!yesorno) {
        usernameBox.classList.add("hidden")
        passwordBox.classList.add("hidden")
        nextButton.classList.add("hidden")
        backButton.classList.add("hidden")
        inputNameBox.classList.add("hidden")
        showInput(currentInputType)
    }
    else {
        usernameBox.classList.remove("hidden")
        passwordBox.classList.remove("hidden")
        nextButton.classList.remove("hidden")
        backButton.classList.remove("hidden")
        inputNameBox.classList.remove("hidden")
        showInput(currentInputType)
    }
}

nextButton.addEventListener("click", async () => {
    if (passwordBox.classList.contains("hidden")) {
        if (usernameBox.value === "") {
            statusBox.innerText = "A username is required!"
            return
        } else {
            statusBox.innerText = "Welcome back, " + usernameBox.value + "!"
        }
        showInput(1)
    } else {
        let username = usernameBox.value
        let password = passwordBox.value

        if (password === "") {
            statusBox.innerText = "A password is required!"
            return
        }

        showInput(2)
        showElements(true)

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

        async function migrateLegacyPassword(secretKey, password) {
            return await fetch("/api/changepassword", {
                method: "POST",
                body: JSON.stringify({
                    secretKey: secretKey,
                    newPassword: password,
                    migration: true
                }),
                headers: {
                    "Content-Type": "application/json; charset=UTF-8",
                }
            })
        }

        async function hashpassold(pass) {
            let key = pass
            for (let i = 0; i < 128; i++) {
                key = await hashwasm.sha3(key)
            }
            return key
        }

        statusBox.innerText = "Hashing password..."
        let hashedPassword = await hashpass(password)

        let response = await fetch("/api/login", {
            method: "POST",
            body: JSON.stringify({
                username: username,
                password: hashedPassword,
                modern: true
            }),
            headers: {
                "Content-Type": "application/json; charset=UTF-8"
            }
        })
        let responseData = await response.json()
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
            statusBox.innerText = "Welcome back!"
            await new Promise(r => setTimeout(r, 200))
            window.location.href = "/app" + window.location.search
        } else if (response.status === 401) {
            if (responseData["migrated"] !== true) {
                statusBox.innerText = "Migrating to new password algorithm..."
                let loginOld = await fetch("/api/login", {
                    method: "POST",
                    body: JSON.stringify({
                        username: username,
                        password: await hashpassold(password),
                        modern: false
                    }),
                    headers: {
                        "Content-Type": "application/json; charset=UTF-8"
                    }
                })
                let loginDataOld = await loginOld.json()
                if (loginOld.status === 401) {
                    statusBox.innerText = "Username or password incorrect!"
                    showInput(1)
                    showElements(true)
                } else if (loginOld.status === 200) {
                    statusBox.innerText = "Setting up encryption keys..."
                    localStorage.setItem("DONOTSHARE-secretkey", loginDataOld["key"])
                    localStorage.setItem("DONOTSHARE-password", await hashwasm.argon2id({
                        password: password,
                        salt: new TextEncoder().encode("I love Burgerauth!!"),
                        parallelism: 1,
                        iterations: 32,
                        memorySize: 19264,
                        hashLength: 32,
                        outputType: "hex"
                    }))

                    statusBox.innerText = "Migrating password..."
                    let status = await migrateLegacyPassword(loginDataOld["key"], hashedPass)
                    if (status.status === 200) {
                        statusBox.innerText = "Welcome back!"
                        await new Promise(r => setTimeout(r, 200))
                        window.location.href = "/app" + window.location.search
                    } else {
                        statusBox.innerText = (await status.json())["error"]
                        showInput(1)
                        showElements(true)
                    }
                }
            } else {
                statusBox.innerText = "Wrong username or password..."
                showInput(1)
                showElements(true)
            }
        } else if (response.status === 500) {
            statusBox.innerText = responseData["error"]
            showInput(1)
            showElements(true)
        } else {
            statusBox.innerText = "Something went wrong! (error code: " + responseData["error"] + ")"
            showInput(1)
            showElements(true)
        }
    }
})

backButton.addEventListener("click", () => {
    showInput(0)
});

showInput(0)

document.getElementById("privacyButton").addEventListener("click", function(event) {
    event.preventDefault();

    const queryString = window.location.search;
    window.location.href = "/privacy" + queryString;
});

function toSignup() {
    window.location.href = "/signup" + window.location.search;
}
