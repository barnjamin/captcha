(async function(){

    let txn;
    let salt;
    let iv;
    let padding;
    let iters;

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

    async function solutionToKey(solution) {
        const passphrase = new Uint8Array(solution.split('').map(c=>{ return parseInt(c) }))

        console.time("import")
        const rawKey = await window.crypto.subtle.importKey(
          "raw", passphrase, "PBKDF2", false, ["deriveBits", "deriveKey"]
        ).then((cryptoKey) => {
          return cryptoKey;
        });
        console.timeEnd("import")

        console.time("deriveBits")
        const bits = await window.crypto.subtle.deriveBits(
          { name: "PBKDF2", hash: "SHA-256", salt: salt, iterations: iters },
          rawKey, 256
        ).then((derivedBits) => {
          return derivedBits;
        });
        console.timeEnd("deriveBits")

        return await crypto.subtle.importKey(
            "raw", bits, "AES-CBC", false, ["decrypt"],
        )
    }

    fetch('/captcha?type=img&lang=en')
        .then(response => response.json())
        .then(data => {
            img.src = prefix + data['captcha']
            txn     = Uint8Array.from(atob(data['txn']), c => { return c.charCodeAt(0)})
            salt    = Uint8Array.from(atob(data['salt']),c => { return c.charCodeAt(0)})
            iv      = Uint8Array.from(atob(data['iv']),  c => { return c.charCodeAt(0)})
            iters   = data['iters']
            padding = data['pad']

            encview.value = txn
        });

})();
