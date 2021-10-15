*DO NOT USE THIS FOR ANYTHING REAL*



This is meant to be an exercise only


Bad stuff
---------

- OCI could break this

- Multithreading and making a ton of guesses could break this

- Sha256 not a great hash function

- No Salting currently so you can prehash all 10k numbers and try them all



TODO
----
- Salt with last round hash && pass the one used to FE?

- Multiple Rounds of Captchas?

    - Distinct combinations of N digits = 10^N

    - Multiple tests M = (10^N)^M

