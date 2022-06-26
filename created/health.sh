#!/bin/sh

app_url="localhost:1234"

# Login with bad creds. confirm with error message
invalid_login=$(curl -s --data "username=badcreds&password=badcreds&action=login" $app_url | grep -c "Invalid Username or Password")
#echo "invalid login error:" $invalid_login

if [ "$invalid_login" -eq 0 ]; then
    echo "0";
    exit 1;
fi

# Login with Admin creds. Grep output for flag return
#admin_login_flag=$(curl -s --data "username=admin&password=adminadminadmin2468&action=login" $app_url | grep -oE "YEET ahead of Peers: flag{.*}")
admin_login_flag=$(curl -s --data "username=admin&password=adminadminadmin2468&action=login" $app_url)
#echo "admin login gets flag:" $admin_login_flag

if [ -z "$admin_login_flag" ]; then
    echo "0";
    exit 1;
fi

# Login with Admin creds. Grep output for session cookie
admin_cookie=$(curl -c - -s --data "username=admin&password=adminadminadmin2468&action=login" $app_url | grep -oE "session\s[A-Za-z0-9+/]*$" | cut -f 2 )
#echo "admin login gets cookie:" $admin_cookie

if [ -z "$admin_cookie" ]; then
    echo "0";
    exit 1;
fi

# Bad cookie. Returns to index
bad_cookie_fail=$(curl -s --cookie "session=badcookie" $app_url | grep -c "<title>ACFT Preview</title>")
#echo "bad cookie returns to index:" $bad_cookie_fail

if [ "$bad_cookie_fail" -eq 0 ]; then
    echo "0";
    exit 1;
fi

# Login with Admin cookie. Grep output for flag return
admin_cookie_flag=$(curl -s --cookie "session=$admin_cookie" $app_url | grep -oE "YEET ahead of Peers: flag{.*}")
#echo "admin cookie gets flag:" $admin_cookie_flag

if [ -z "$admin_cookie_flag" ]; then
    echo "0";
    exit 1;
fi

# Logout with Admin cookie returns to index.html.
admin_logout=$(curl -s --data "action=logout" --cookie "session=$admin_cookie" $app_url | grep -c "<title>ACFT Preview</title>")
#echo "admin logout return to index:" $admin_logout

if [ "$admin_logout" -eq 0 ]; then
    echo "0";
    exit 1;
fi

# Logout with Admin cookie clears cookie.
admin_logout_cookie=$(curl -s -c - --data "action=logout" --cookie "session=$admin_cookie" $app_url | grep -oE "session\s[A-Za-z0-9+/=]*$" | cut -f 2 )
#echo "admin cookie after logout:" $admin_logout_cookie

if ! [ -z "$admin_logout_cookie" ]; then
    echo "0";
    exit 1;
fi

# Register new user. Grep output for confirmation message
new_user_registration=$(curl -s --data "username=healthcheck&password=healthcheck&action=register" $app_url | grep -c "Successfully added new user 'healthcheck'")
#echo "registered new user:" $new_user_registration

if [ "$new_user_registration" -eq 0 ]; then
    echo "0";
    exit 1;
fi

# Login as new user. Grep output for user name confirmation
new_user_name=$(curl -s --data "username=healthcheck&password=healthcheck&action=login" $app_url | grep -c "Welcome healthcheck")
#echo "new user login confirms username:" $new_user_name

if [ "$new_user_name" -eq 0 ]; then
    echo "0";
    exit 1;
fi

# Login as new user. Grep output for message return
new_user_message=$(curl -s --data "username=healthcheck&password=healthcheck&action=login" $app_url | grep -o "Maybe if you were an admin you could YEET")
#echo "new user login gets message:" $new_user_message

if [ -z "$new_user_message" ]; then
    echo "0";
    exit 1;
fi

# Login as new user. confirm new cookie
new_user_cookie=$(curl -c - -s --data "username=healthcheck&password=healthcheck&action=login" $app_url | grep -oE "session\s[A-Za-z0-9+/=]*$" | cut -f 2 )
#echo "new user login gets new cookie:" $new_user_cookie

if [ "$new_user_cookie" = "$admin_cookie" ]; then
    echo "0";
    exit 1;
fi

# Delete new user. Confirm with success message
delete_user=$(curl -s --cookie "session=$new_user_cookie" --data "action=delete+user" $app_url | grep -c "Successfully deleted user 'healthcheck'" )
#echo "deleted new user:" $delete_user

if [ "$delete_user" -eq 0 ]; then
    echo "0";
    exit 1;
fi

# Login with deleted creds. confirm with error message
deleted_user_login=$(curl -s --data "username=healthcheck&password=healthcheck&action=login" $app_url | grep -c "Invalid Username or Password")
#echo "invalid login error:" $deleted_user_login

if [ "$deleted_user_login" -eq 0 ]; then
    echo "0";
    exit 1;
fi

# Cant delete user without cookie. Returns to index
delete_no_cookie=$(curl -s --cookie "session=badcookie" --data "action=delete+user" $app_url | grep -c "<title>ACFT Preview</title>" )
#echo "no cookie no delete:" $delete_no_cookie

if [ "$delete_no_cookie" -eq 0 ]; then
    echo "0";
    exit 1;
fi

# Cant delete admin user. Confirm with error message
delete_admin=$(curl -s --cookie "session=$admin_cookie" --data "action=delete+user" $app_url | grep -c "Cannot delete Admin user &#39;admin&#39" )
#echo "cannot delete admin:" $delete_admin

if [ "$delete_admin" -eq 0 ]; then
    echo "0";
    exit 1;
fi

# Report it
echo "1"
