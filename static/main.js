(async function(){

    let txn;
    let txnid;
    let iv;
    let padding;

    const prefix = "data:image/png;base64,"

    const img       = document.getElementById("captcha")
    const solution  = document.getElementById("solution")
    const button    = document.getElementById("check")
    const encview   = document.getElementById("encrypted")
    const decview   = document.getElementById("decrypted")

    button.onclick = async function () {
        try {
            const key = await solutionToKey(solution.value)
            const decrypted = await decryptTxn(key)
            decview.value = JSON.stringify(decrypted)
        } catch (error) {
            console.error(error)
        }
    }

    async function decryptTxn(key) {
        const decrypted = new Uint8Array(await window.crypto.subtle.decrypt(
            { name: "AES-CBC",  iv: iv }, key, txn 
        ));

        const unpadded = decrypted.slice(0, decrypted.length-padding)
        const stxn = algosdk.decodeSignedTransaction(unpadded)
        return stxn 
    }

    async function solutionToKey(msg) {
        const bytes = new Uint8Array(msg.split('').map(c=>{ return parseInt(c) }))
        const tohash = new Uint8Array([...bytes, ...txnid])
        const hbuff = await crypto.subtle.digest('SHA-256', tohash);
        const hash = new Uint8Array(hbuff)
        return await crypto.subtle.importKey(
            "raw", hash, "AES-CBC", false, ["decrypt"],
        )
    }

    fetch('/captcha?type=img&lang=en')
        .then(response => response.json())
        .then(data => {
            img.src = prefix + data['captcha']
            txn     = Uint8Array.from(atob(data['txn']), c => { return c.charCodeAt(0)})
            txnid   = Uint8Array.from(atob(data['txid']),c => { return c.charCodeAt(0)})
            iv      = Uint8Array.from(atob(data['iv']),  c => { return c.charCodeAt(0)})
            padding = data['pad']

            encview.value = txn
        });

})();
