// Add an event listener to handle incoming messages
window.addEventListener("message", function(event) {
    const access_token = event.data;

    fetch("https://auth.hectabit.org/api/loggedin", {
        method: "POST",
        body: JSON.stringify({
            access_token: access_token
        })
    })
    .then((response) => function () {
        if (response.status === 200) {
            console.log("Key is valid")
            window.postMessage(localStorage.getItem("DONOTSHARE-password"), event.origin)
        }
    })
});