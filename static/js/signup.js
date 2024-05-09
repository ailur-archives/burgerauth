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

let remote = localStorage.getItem("homeserverURL")
if (remote == null) {
    localStorage.setItem("homeserverURL", "https://auth.hectabit.org")
    remote = "https://auth.hectabit.org"
}

let usernameBox = document.getElementById("usernameBox")
let passwordBox = document.getElementById("passwordBox")
let statusBox = document.getElementById("statusBox")
let signupButton = document.getElementById("signupButton")
let captchaBox = document.getElementById("captchaBox")
let unique_token = document.getElementById("passthrough").innerText

function showElements(yesorno) {
    if (!yesorno) {
        usernameBox.classList.add("hidden")
        passwordBox.classList.add("hidden")
        signupButton.classList.add("hidden")
    }
    else {
        usernameBox.classList.remove("hidden")
        passwordBox.classList.remove("hidden")
        signupButton.classList.remove("hidden")
    }
}

document.addEventListener('DOMContentLoaded', function() {
    document.getElementById("homeserver").innerText = "Your homeserver is: " + remote + ". "
});

signupButton.addEventListener("click", () => {
    async function doStuff() {
        let username = usernameBox.value
        let password = passwordBox.value
        let captcha = captchaBox.value

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
        if (captcha === "") {
            statusBox.innerText = "Please complete the captcha!"
            return
        }

        showElements(false)
        statusBox.innerText = "Creating account, please hold on..."

        async function hashpass(pass) {
            let key = pass
            for (let i = 0; i < 128; i++) {
                key = await hashwasm.sha3(key)
            }
            return key
        }


        fetch(remote + "/api/signup", {
            method: "POST",
            body: JSON.stringify({
                username: username,
                password: await hashpass(password),
                captcha: captcha,
                unique_token: unique_token
            }),
            headers: {
                "Content-Type": "application/json; charset=UTF-8"
            }
        })
            .then((response) => response)
            .then((response) => {
                async function doStuff() {
                    let responseData = await response.json()
                    console.log(responseData)

                    if (response.status === 200) {
                        statusBox.innerText = "Redirecting..."
                        localStorage.setItem("DONOTSHARE-secretkey", responseData["key"])
                        localStorage.setItem("DONOTSHARE-password", await hashwasm.sha512(password))

                        window.location.href = "/app" + window.location.search
                    }
                    else if (response.status === 409) {
                        statusBox.innerText = "Username already taken!"
                        showElements(true)
                    }
                    else {
                        statusBox.innerText = "Something went wrong!"
                        showElements(true)
                    }
                }
                doStuff()
            });
    }
    doStuff()
});

document.getElementById("loginButton").addEventListener("click", function(event) {
    event.preventDefault();

    const queryString = window.location.search;
    window.location.href = "/login" + queryString;
});

document.getElementById("privacyButton").addEventListener("click", function(event) {
    event.preventDefault();

    const queryString = window.location.search;
    window.location.href = "/privacy" + queryString;
});
