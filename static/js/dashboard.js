if (localStorage.getItem("DONOTSHARE-secretkey") === null) {
    window.location.replace("/login")
    document.body.innerHTML = "Redirecting..."
    throw new Error();
}
let remote = localStorage.getItem("homeserverURL")
if (remote == null) {
    localStorage.setItem("homeserverURL", "https://auth.hectabit.org")
    remote = "https://auth.hectabit.org"
}


function attempt() {
    if (document.getElementById("appidbox").value.match(/^[A-Za-z]+$/)) {
        fetch(origin + "/api/newauth", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                name: document.getElementById("appidbox").value,
                rdiruri: document.getElementById("rdiruribox").value,
                secretKey: localStorage.getItem("DONOTSHARE-secretkey")
            })
        })
        .then(response => {
            async function doStuff() {
                let code = await response.json()
                if (response.status === 200) {
                    document.getElementById("status").innerText = "Your secret key is: " + code["key"] + " and your client id is: " + code["appId"] + ". This will only be shown once!"
                    getauths();
                } else if (response.status === 500) {
                    document.getElementById("status").innerText = "Whoops... Something went wrong. Please try again later. (Error Code 500)"
                } else if (response.status === 401) {
                    document.getElementById("status").innerText = "AppID already taken. (Error Code 401)"
                } else {
                    document.getElementById("status").innerText = "Unkown error encountered. (Error Code " + response.status + ")"
                }
            }
            doStuff()
        })
    }
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
    .then((response) => {
        async function doStuff() {
            let responseData = await response.json()
            document.querySelectorAll(".oauthentry").forEach((el) => el.remove());
            for (let i in responseData) {
                let oauthElement = document.createElement("div")
                let oauthText = document.createElement("p")
                let oauthName = document.createElement("p")
                let oauthUrl = document.createElement("p")
                let oauthRemoveButton = document.createElement("button")
                oauthText.innerText = "Client ID: " + responseData[i]["appId"]
                oauthName.innerText = "App name: " + responseData[i]["name"]
                oauthUrl.innerText = "Redirect Url: " + responseData[i]["rdiruri"]
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
                oauthElement.append(oauthRemoveButton)
                oauthElement.classList.add("oauthentry")

                document.getElementById("oauthlist").append(oauthElement)
            }
        }
        doStuff()
    });
}

getauths()
