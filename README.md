*DO NOT USE THIS FOR ANYTHING REAL*

_This is meant to be an exercise only_


Captcha Service
---------------

Provides a way to validate that a user has passed a captcha test by allowing them to submit an authority signed transaction that can only be decrypted with the solution to a captcha.

This service generates a captcha and a signed payment transaction (0 amt, 0 fee) from a "trusted authority" account. The bytes of the payment transaction are encrypted with a key generated from the solution to the captcha. The captcha and encrypted transaction are provided in as a json response to an HTTP request. When a user is presented with the captcha challenge, entering the correct solution will generate the correct key to decrypt the transaction.  This transaction can then be submitted to the network with some other transactions and on chain logic may check that the authority address has co-signed the transaction group.


Details
-------

Currently a new account is generated every time the service is restarted. This would need to be static in an actual solution and known ahead of time for any contract that might want to check that the transaction group is cosigned.


Key generation is done using [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) to provide a better key from such a low entropy source as well as some time cost to an attacker. The captcha solution is the password, we're using the generated transaction id as a salt, and its currently configured to run for 10e5 iterations. In my browser this 10e5 iteration key generation takes about half a second. The number of iterations can be increased to provide a greater challenge to attackers.


|iters |time  |
|------|------|
|10e3  |13ms  |
|10e4  |75ms  |
|10e5  |604ms |
|10e6  |5941ms|


Encryption/Decryption is done using AES-CBC though there is no specific reason to have chosen this mode.


To run it:

```sh
git clone https://github.com/barnjamin/captcha
cd captcha
go get
go run main.go
```
In a browser visit https://localhost:8443 and proceed through scary warning screens.

Because the native cryptographic libraries are used, they must be loaded in a secure context over HTTPS. This comes with a self signed certificate which browsers don't like.


Bad stuff
---------

- OCR could break this

- Parallel brute forcing could break this

- Click farms/fivver/mechanical turk could break this

TODO
----

- Sign bytes instead? Only pass signature for txn? Send custom AppCall instead? 

- Allow specific GroupId to be passed and added to the transaction

- Multiple Rounds of Captchas?

    - Distinct combinations of N digits = 10^N,  multiple tests M = (10^N)^M
