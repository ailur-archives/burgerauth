async function main() {
    const response = await fetch("/api/aeskeyshare", {
        method: "POST",
        body: JSON.stringify({
            access_token: urlParams.get('token')
        }),
        headers: {
            "Content-Type": "application/json; charset=UTF-8"
        }
    });
    if (response.status === 200) {
        let responseData = await response.json();
        const message = await hashwasm.argon2id({
            password: localStorage.getItem("DONOTSHARE-password") + responseData["appId"],
            salt: new TextEncoder().encode("Burgers are yum!"),
            parallelism: 1,
            iterations: 32,
            memorySize: 19264,
            hashLength: 32,
            outputType: "hex"
        });
        window.postMessage("finished", "*");
        console.log("finished")
        localStorage.setItem("DONOTSHARE-EXCHANGED-KEY", responseData[message]);
    } else {
        console.error("Error:", response.status);
    }
}

window.onload = main;
