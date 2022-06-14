web 0 - 77 points, 65 solves

category: baby/web

original description:
    Check out my cool new website!
    [website link]

my files:
    solve.sh - curl command solving the task
    app.js - source code of the app (it was displayed on the webpage)

---- writeup ----
As we can see the app is rather simple, it expects two variables: "first" and "second", sent with POST on path /flag.
It then tests those two variables - they should not be equal, according to the !== operator, but should result in
identical sha1 hashes.

The fact that the variables are appended to a salt (constant string "pepper") before being hashed allows us to use
some type juggling. In Javascript, if we add a string and, for instance, an array, the result will still be a string,
for instance, "pepper" + [1] results in a string "pepper1", just like "pepper" + "1" would, but at the same time
[1] and "1" will not test to be equal according to the !== operator because they are not of the same type.
Thankfully, we are able to pass arrays in POST parameters using this syntax: "array[]=1".

If we then send POST request with "first[]=1&second=1" as body, the server will respond with the flag, solve.sh does exactly that.

flag: SUSEC{YOUR3_4B0UT_TO_H4CK_TIM3_RU_SURE}

---- thoughts ----
Very simple challenge, good to notice that similar techniques may apply to PHP which is also famous for its type juggling.
