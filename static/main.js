(async function(){

    let txn;
    let iv;

    const prefix = "data:image/png;base64,"

    const img       = document.getElementById("captcha")
    const solution  = document.getElementById("solution")
    const button    = document.getElementById("check")

    button.onclick = async function () {
        try {
            const key = await solutionToKey(solution.value)
            alert("Decrypted message: "+ await decrypt(key))
        } catch (error) {
            console.error(error)
        }
    }

    async function decrypt(key) {
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-CBC",  iv: iv }, key, txn 
        );

        return new TextDecoder("utf-8").decode(decrypted)
    }

    async function solutionToKey(msg) {
        const bytes = new Uint8Array(msg.split('').map(c=>{ return parseInt(c) }))
        const hbuff = await crypto.subtle.digest('SHA-256', bytes);
        const hash = new Uint8Array(hbuff)
        return await crypto.subtle.importKey(
            "raw", hash, "AES-CBC", false, ["decrypt"],
        )
    }

    fetch('/captcha?type=img&lang=en')
        .then(response => response.json())
        .then(data => {
            img.src = prefix + data['captcha']
            txn  = Uint8Array.from(atob(data['txn']), c => { return c.charCodeAt(0)})
            iv  = Uint8Array.from(atob(data['iv']), c => { return c.charCodeAt(0)})
        });

})();