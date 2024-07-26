if (localStorage.getItem("DONOTSHARE-secretkey") === null) {
    window.location.replace("/login")
    document.body.innerHTML = "Redirecting..."
    throw new Error();
}

function attempt() {
    if (document.getElementById("appidbox").value !== "") {
        let openid = false;
        if (document.getElementById("openidbox").checked) {
            openid = true
        }
        let scopes = []
        if (openid) {
            scopes.push("openid")
        }
        if (document.getElementById("aeskeysharebox").value !== "") {
            scopes.push("aeskeyshare")
        }
        fetch(origin + "/api/newauth", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                name: document.getElementById("appidbox").value,
                redirectUri: document.getElementById("rdiruribox").value,
                secretKey: localStorage.getItem("DONOTSHARE-secretkey"),
                scopes: JSON.stringify(scopes),
                keyShareUri: document.getElementById("aeskeysharebox").value
            })
        })
        .then(async response => {
            let code = await response.json()
            document.getElementById("appidbox").value = ""
            document.getElementById("rdiruribox").value = ""
            document.getElementById("aeskeysharebox").value = ""
            document.getElementById("openidbox").checked = false
            if (response.status === 200) {
                document.getElementById("status").innerText = "Your secret key is: " + code["key"] + " and your client id is: " + code["appId"] + ". This will only be shown once!"
                getauths();
            } else if (response.status === 500) {
                document.getElementById("status").innerText = code["error"]
            } else if (response.status === 401) {
                document.getElementById("status").innerText = "AppID already taken. (Error Code: " + code["error"] + ")"
            } else {
                document.getElementById("status").innerText = "Unknown error encountered. (Error Code:" + code["error"] + ")"
            }
        })
    }
}

function getSessions() {
    fetch(origin + "/api/sessions/list", {
        method: "POST",
        body: JSON.stringify({
            secretKey: localStorage.getItem("DONOTSHARE-secretkey")
        }),
        headers: {
            "Content-Type": "application/json; charset=UTF-8"
        }
    })
        .then(async (response) => {
            let responseData = await response.json()
            if (response.status === 200) {
                if (responseData === null || responseData.length === 0) {
                    let statusText = document.createElement("p")
                    statusText.classList.add("sessionInfo")
                    statusText.innerText = "Hi there! You don't have any sessions logged in, somehow. Congratulations on breaking the laws of physics!"
                    document.getElementById("sessionsList").append(statusText)
                } else {
                    document.querySelectorAll(".sessionInfo").forEach(e => e.remove())
                    document.querySelectorAll(".sessionentry").forEach(e => e.remove())
                    for (let i in responseData) {
                        let sessionElement = document.createElement("div")
                        let sessionDevice = document.createElement("p")
                        let sessionRemoveButton = document.createElement("button")
                        let sessionImage = document.createElement("img")
                        if (responseData[i]["thisSession"]) {
                            sessionDevice.innerText = "(current) " + responseData[i]["device"]
                        } else {
                            sessionDevice.innerText = responseData[i]["device"]
                        }

                        if (responseData[i]["device"].includes("NT") || responseData[i]["device"].includes("Linux") || responseData[i]["device"].includes("Macintosh")) {
                            sessionImage.src = "/static/svg/device_computer.svg"
                        } else if (responseData[i]["device"].includes("iPhone" || responseData[i]["device"].includes("Android") || responseData[i]["device"].includes("iPod"))) {
                            sessionImage.src = "/static/svg/device_smartphone.svg"
                        } else if (responseData[i]["device"].includes("curl")) {
                            sessionImage.src = "/static/svg/device_terminal.svg"
                        } else {
                            sessionImage.src = "/static/svg/device_other.svg"
                        }

                        sessionRemoveButton.innerText = "Remove session"
                        sessionRemoveButton.addEventListener("click", () => {
                            fetch(origin + "/api/deleteauth", {
                                method: "POST",
                                body: JSON.stringify({
                                    secretKey: localStorage.getItem("DONOTSHARE-secretkey"),
                                    appId: responseData[i]["appId"]
                                }),
                                headers: {
                                    "Content-Type": "application/json; charset=UTF-8"
                                }
                            })
                            sessionElement.remove()
                            if (responseData[i]["thisSession"]) {
                                window.location.replace("/logout")
                            }
                        });

                        sessionElement.append(sessionImage)
                        sessionElement.append(sessionDevice)
                        sessionElement.append(sessionRemoveButton)
                        sessionElement.classList.add("sessionentry")

                        document.getElementById("sessionsList").append(sessionElement)
                    }
                }
            } else if (response.status === 500) {
                let statusText = document.createElement("p")
                statusText.classList.add("sessionInfo")
                statusText.innerText = responseData["error"]
                document.getElementById("sessionsList").append(statusText)
            } else {
                let statusText = document.createElement("p")
                statusText.classList.add("sessionInfo")
                statusText.innerText = "Something went wrong! (error code: " + responseData["error"] + ")"
                document.getElementById("sessionsList").append(statusText)
            }
        });
}

function getauths() {
    fetch(origin + "/api/listauth", {
        method: "POST",
        body: JSON.stringify({
            secretKey: localStorage.getItem("DONOTSHARE-secretkey")
        }),
        headers: {
            "Content-Type": "application/json; charset=UTF-8"
        }
    })
    .then(async (response) => {
        let responseData = await response.json()
        if (response.status === 200) {
            if (responseData === null || responseData.length === 0) {
                let statusText = document.createElement("p")
                statusText.classList.add("authInfo")
                statusText.innerText = "Hi there! You don't have any OAuth2 clients yet. Create one above!"
                document.getElementById("oauthlist").append(statusText)
            } else {
                document.querySelectorAll(".authInfo").forEach(e => e.remove())
                document.querySelectorAll(".oauthentry").forEach(e => e.remove())
                for (let i in responseData) {
                    let oauthElement = document.createElement("div")
                    let oauthText = document.createElement("p")
                    let oauthName = document.createElement("p")
                    let oauthUrl = document.createElement("p")
                    let oauthRemoveButton = document.createElement("button")
                    oauthText.innerText = "Client ID: " + responseData[i]["appId"]
                    oauthName.innerText = "App name: " + responseData[i]["name"]
                    oauthUrl.innerText = "Redirect Url: " + responseData[i]["redirectUri"]
                    oauthRemoveButton.innerText = "Delete Permanently"
                    oauthRemoveButton.addEventListener("click", () => {
                        if (window.confirm("Are you SURE you would like to delete this FOREVER?") === true) {
                            fetch(origin + "/api/deleteauth", {
                                method: "POST",
                                body: JSON.stringify({
                                    secretKey: localStorage.getItem("DONOTSHARE-secretkey"),
                                    appId: responseData[i]["appId"]
                                }),
                                headers: {
                                    "Content-Type": "application/json; charset=UTF-8"
                                }
                            })
                            oauthElement.remove()
                        }
                    });

                    oauthElement.append(oauthText)
                    oauthElement.append(oauthName)
                    oauthElement.append(oauthUrl)

                    let openid = false
                    let aesKeyShare = false
                    let scopes = JSON.parse(responseData[i]["scopes"])
                    for (let n in scopes) {
                        console.log(scopes[n])
                        if (scopes[n] === "openid") {
                            openid = true
                        } else if (scopes[n] === "aeskeyshare") {
                            if (responseData[i]["keyShareUri"] !== "none") {
                                aesKeyShare = true
                                let keyShareUri = document.createElement("p")
                                keyShareUri.innerText = "Key Share URI: " + responseData[i]["keyShareUri"]
                                oauthElement.append(keyShareUri)
                            }
                        }
                    }

                    let scopeTxt = document.createElement("p")
                    if (openid || aesKeyShare) {
                        scopeTxt.innerText = "Scopes: "
                        if (openid) {
                            scopeTxt.innerText += "openid"
                        }
                        if (aesKeyShare) {
                            if (!openid) {
                                scopeTxt.innerText += "aeskeyshare"
                            } else {
                                scopeTxt.innerText += ", aeskeyshare"
                            }
                        }
                    } else {
                        scopeTxt.innerText = "You have not defined any scopes for this client."
                    }

                    oauthElement.append(scopeTxt)
                    oauthElement.append(oauthRemoveButton)
                    oauthElement.classList.add("oauthentry")

                    document.getElementById("oauthlist").append(oauthElement)
                }
            }
        } else if (response.status === 500) {
            let statusText = document.createElement("p")
            statusText.classList.add("authInfo")
            statusText.innerText = responseData["error"]
            document.getElementById("oauthlist").append(statusText)
        } else {
            let statusText = document.createElement("p")
            statusText.classList.add("authInfo")
            statusText.innerText = "Something went wrong! (error code: " + responseData["error"] + ")"
            document.getElementById("oauthlist").append(statusText)
        }
    });
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

async function deleteacct() {
    if (confirm("Are you SURE you would like to delete your account forever?") === true) {
        await fetch("/api/deleteaccount", {
            method: "POST",
            body: JSON.stringify({
                "secretKey": localStorage.getItem("DONOTSHARE-secretkey")
            }),
            headers: {
                "Content-Type": "application/json; charset=UTF-8"
            }
        })
            .then((response) => response)
            .then((response) => {
                async function doStuff() {
                    if (response.status === 200) {
                        parent.window.location.href = '/logout';
                    }
                }
                doStuff()
            });
    }
}

document.addEventListener("DOMContentLoaded", () => {
    checkNetwork().then(async (result) => {
        if (result) {
            getauths()
            getSessions()
            let response = await fetch("/api/userinfo", {
                method: "POST",
                body: JSON.stringify({
                    "secretKey": localStorage.getItem("DONOTSHARE-secretkey")
                }),
                headers: {
                    "Content-Type": "application/json; charset=UTF-8"
                }
            })
            const data = await response.json()
            if (response.status === 200) {
                document.getElementById("namebox").innerText = "Username: " + data["username"];
                document.getElementById("datebox").innerText = "Account created: " + new Date(data["created"] * 1000).toLocaleString();
            }
        }
    })
})

document.getElementById("devAcctSwitcher").addEventListener("click", () => {
    document.getElementById("developers").classList.toggle("hidden")
    document.getElementById("account").classList.toggle("hidden")
    if (document.getElementById("devAcctSwitcher").innerText === "Switch to developer view") {
        document.getElementById("devAcctSwitcher").innerText = "Switch to account view"
    } else {
        document.getElementById("devAcctSwitcher").innerText = "Switch to developer view"
    }
})