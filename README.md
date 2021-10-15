*DO NOT USE THIS FOR ANYTHING REAL*



_This is meant to be an exercise only_



To run it:

`go run main.go`

go to https://localhost:8443 and proceed through warning screens

this must be https or the js crypto libs wont load, self signed key so browsers dont like it



Bad stuff
---------

- OCI could break this

- Multithreading and making a ton of guesses could break this

- Sha256 not a great hash function

- No Salting currently so you can prehash all 10k numbers and try them all



TODO
----

- Actually send a transaction

- Set LastValid-FirstValid low enough that itll work for a human but a program will have trouble guessing all the results

- Salt with last round hash && pass the one used to FE?

- Multiple Rounds of Captchas?

    - Distinct combinations of N digits = 10^N

    - Multiple tests M = (10^N)^M

