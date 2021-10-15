*DO NOT USE THIS FOR ANYTHING REAL*



_This is meant to be an exercise only_



To run it:

`go run main.go`

go to https://localhost:8443 and proceed through warning screens

this must be https or the js crypto libs wont load, self signed key so browsers dont like it



Bad stuff
---------

- OCR could break this

- Multithreading and making a ton of guesses could break this

- Sha256 not a great hash function



TODO
----

- Allow specific group id to be passed and added to the transaction

- Multiple Rounds of Captchas?

    - Distinct combinations of N digits = 10^N

    - Multiple tests M = (10^N)^M

