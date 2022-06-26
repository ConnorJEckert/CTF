# The Overhead Yeet Event

This event is themed around the second event of the Army Comabat Fitness Test.
User is promped with a login screen with a username and password field. 
The options to login or register a new user are given.
If the user logs in as an admin level user, they will be given the flag
Once logged in, there is the option to logout or to delete that user


## Bugs

There are a few intentional bugs:

1. Unsantized user input on login fields. Allows for sql injection
2. Unsantized user input on regeristering new user. Including admin column in query when not used. Allows for attacker to set new user's privs to admin
3. Use of `executescript()` instead of `execute()`. Allows user to chain multiple sql statements together for full sql control
4. Cookies are just base64'd strings with isAdmin parameter. Only check is that its a valid username

## Testing

There is a script, `./test.sh` that allows you to play with the challenge outside of the NCOIC construct.
