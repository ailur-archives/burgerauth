window.addEventListener("message", function(event) {
    try {
        let data = JSON.parse(event.data);
        const access_token = data["access_token"];
        const redirect_uri = data["redirect_uri"];

        fetch("https://auth.hectabit.org/api/isloggedin", {
            method: "POST",
            body: JSON.stringify({
                access_token: access_token
            })
        })
            .then((response) => {
                if (response.status === 200) {
                    console.log("Key is valid");
                    let newtab = window.open(redirect_uri);
                    newtab.postMessage(localStorage.getItem("DONOTSHARE-password"), "*");
                    window.close();
                }
            });
    } catch {
        console.log("Error parsing JSON");
    }
});
