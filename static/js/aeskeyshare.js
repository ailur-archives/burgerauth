// Add an event listener to handle incoming messages
window.addEventListener("message", function(event) {
    const access_token = event.data;

    fetch("https://auth.hectabit.org/api/loggedin", {
        method: "POST",
        body: JSON.stringify({
            access_token: access_token
        })
    })
    .then((response) => response)
    .then((response) => {
        async function doStuff() {
            let responseData = await response.json()
            if (response.status === 200) {
                console.log("Key is valid")
                let key = localStorage.getItem("DONOTSHARE-password").concat(responseData["appId"]);
                for (let i = 0; i < 128; i++) {
                    key = await hashwasm.sha3(key)
                }
                parent.window.postMessage(key, "*")
            }
            console.log("Alive check!")
        }
        console.log("Running doStuff")
        doStuff();
    })
    console.log("The script is running!")
});
