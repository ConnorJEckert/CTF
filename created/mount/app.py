#!/usr/bin/env python3

import binascii
import hashlib
import sqlite3
import base64
from flask import Flask, request, render_template, make_response

app = Flask(__name__)
FLAGFILE = "/svc/flag.txt"
USERDATABASE = "/svc/mount/users.db"
HOSTIP = "0.0.0.0"
PORT = 1234


def get_flag_text():
    try:
        with open(FLAGFILE, 'r', encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "Error getting Flag.txt"


def encode_cookie(user_data):
    try:
        user_bytes = str(list(user_data)).encode('ascii')
        return base64.b64encode(user_bytes)
    except TypeError:
        return ""


def decode_cookie(cookie):
    try:
        user_bytes = base64.b64decode(cookie)
        user_str = user_bytes.decode('ascii')
        user_list = user_str[1:-1].split(", ")
        return [
            int(user_list[0]), user_list[1][1:-1], user_list[2][1:-1],
            int(user_list[3])
        ]
    except (UnicodeDecodeError, binascii.Error):
        return [None, None, None, None]


def clear_cookie_response():
    resp = make_response(render_template('index.html'))
    resp.set_cookie('session', "")
    return resp


def error_response(err, statement=None):
    if statement is not None:
        resp = make_response(
            render_template('index.html',
                            error=str(err) + f" for statement {statement}"))
    else:
        resp = make_response(render_template('index.html', error=str(err)))
    resp.set_cookie('session', "")
    return resp


def generate_hash_str(mystery):
    mystery_hash = hashlib.md5(mystery.encode('ascii'))
    return mystery_hash.hexdigest()


def login_response(user, pwd, db_cursor):
    try:
        statement = "SELECT * FROM users WHERE username='" + user + "' AND password='" + generate_hash_str(
            pwd) + "'"
        db_cursor.execute(statement)
        selected_user = db_cursor.fetchall()

        if selected_user == []:
            return error_response("Invalid Username or Password")

        if selected_user[0][3] == 1:
            resp = make_response(
                render_template('webpage.html',
                                user=user,
                                flag=get_flag_text()))
        else:
            resp = make_response(render_template('webpage.html', user=user))
        resp.set_cookie('session', encode_cookie(selected_user[0]))
        return resp

    except sqlite3.Error as err:
        return error_response(err, statement)


def register_response(user, pwd, db_cursor):
    try:
        statement = "INSERT INTO users (username, password, admin) VALUES ('" + user + "','" + generate_hash_str(
            pwd) + "', 0)"
        db_cursor.executescript(statement)
        return render_template('index.html', registered_user=user)

    except sqlite3.Error as err:
        return error_response(err, statement)


def delete_user_response(user_cookie, db_cursor):
    user_info = decode_cookie(user_cookie)
    if user_info[0] is not None:
        user = user_info[1]
        pwd_hash = user_info[2]
        is_admin = user_info[3]
        try:
            if is_admin > 0:
                return error_response(f"Cannot delete Admin user '{user}'")
            statement = "DELETE FROM users WHERE username='" + user + "' AND password='" + pwd_hash + "' AND admin=" + str(
                is_admin) + ";"
            db_cursor.executescript(statement)
            resp = make_response(
                render_template('index.html', deleted_user=user))
            resp.set_cookie('session', "")
            return resp

        except sqlite3.Error as err:
            return error_response(err, statement)

    return clear_cookie_response()


def cookie_response(user_cookie, db_cursor):
    user_data = decode_cookie(user_cookie)
    is_admin = user_data[-1]
    username = user_data[1]
    if (username is not None) and (is_admin is not None):
        try:
            statement = "SELECT * FROM users WHERE username='" + username + "'"
            db_cursor.execute(statement)
            selected_user = db_cursor.fetchall()

            if selected_user == []:
                return clear_cookie_response()

            if is_admin == 1:
                return make_response(
                    render_template('webpage.html',
                                    user=username,
                                    flag=get_flag_text()))
            return make_response(render_template('webpage.html',
                                                 user=username))
        except sqlite3.Error as err:
            return error_response(err, statement)
    return clear_cookie_response()


@app.route("/", methods=["POST", "GET"])
def main():
    db_conn = sqlite3.connect(USERDATABASE)
    db_cursor = db_conn.cursor()

    if request.method == "POST":

        action = request.form["action"]

        user_cookie = request.cookies.get('session')
        if user_cookie and action == "delete user":
            return delete_user_response(user_cookie, db_cursor)

        if action == "logout":
            return clear_cookie_response()

        user = request.form["username"]
        pwd = request.form["password"]

        if action == "login":
            return login_response(user, pwd, db_cursor)

        if action == "register":
            return register_response(user, pwd, db_cursor)

        return render_template('index.html')

    if request.method == "GET":
        user_cookie = request.cookies.get('session')
        if user_cookie:
            return cookie_response(user_cookie, db_cursor)

        return clear_cookie_response()

    return "Record not found", 400


if __name__ == "__main__":
    app.run(host=HOSTIP, port=PORT)
