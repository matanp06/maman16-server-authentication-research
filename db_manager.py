import hashlib
import json
import os
import secrets
import sqlite3
import time
import uuid
import pyotp
from os import getenv

import argon2
import bcrypt
from argon2 import PasswordHasher

pass_hasher = PasswordHasher(
    time_cost=1,
    memory_cost=65536,
    parallelism=1,
)

security=os.getenv("SECURITY")

totp_list = {}

#connecting to the db and creating it if it doesn't exist
def config_db():
    connection = sqlite3.connect('database.db')
    connection.execute("""CREATE TABLE IF NOT EXISTS USERS (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 
    username TEXT NOT NULL UNIQUE,
    password_plain TEXT NOT NULL,
    password_hash TEXT,
    salt TEXT,
    password_salt_hash TEXT,
    password_pepper_hash TEXT,
    password_bcrypt TEXT,
    password_argon2 TEXT,
    totp_secret TEXT)""")
    connection.execute("""CREATE TABLE IF NOT EXISTS USER_SPECS (
    user_id INTEGER PRIMARY KEY NOT NULL, 
    group_number INTEGER NOT NULL DEFAULT 0,
    last_login TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    is_locked BOOLEAN NOT NULL DEFAULT FALSE,
    last_token_update TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    token_counts INTEGER NULL DEFAULT 0)
    """)

    connection.commit()
    connection.close()

    print("db is connected")

#add user if username is not in use already
#if returns error
def add_user(username, password,secret=None):

    #creating all the passwords needed for this experiment
    #using all of them in the same DB for convenience of usage
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    salt = secrets.token_urlsafe(16)
    password_salt = (password+salt).encode('utf-8')
    password_salt_hash = hashlib.sha256(password_salt).hexdigest()
    password_pepper = (password+salt+os.getenv("PEPPER")).encode('utf-8')
    password_pepper_hash = hashlib.sha256(password_pepper).hexdigest()
    password_bcrypt = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    password_argon2 = pass_hasher.hash(password)

    if secret is None:
        secret = pyotp.random_base32(32)

    try:
        #adding user and it's passwords to the db
        with sqlite3.connect('database.db') as connection:
            cursor = connection.cursor()
            cursor.execute("""INSERT INTO USERS (username,
             password_plain,
             password_hash,
             salt,
             password_salt_hash,
             password_pepper_hash,
             password_bcrypt,
             password_argon2,
             totp_secret) VALUES (?,?,?,?,?,?,?,?,?)""",
                           (username,
                            password,
                            password_hash,
                            salt,
                            password_salt_hash,
                            password_pepper_hash,
                            password_bcrypt,
                            password_argon2,
                            secret,))
            user_id = cursor.lastrowid
            cursor.execute("INSERT INTO USER_SPECS (user_id) VALUES (?) ", (user_id,))
            connection.commit()
        return json.dumps({"status":"registered successfully","secret":secret})

    #username is already exists
    except sqlite3.IntegrityError:
        return json.dumps({"status": "failed","reason":"user already exists"})




# trying to authenticate the user credentials
def authenticate(username, password):
    try:
        #connecting to the db
        with (sqlite3.connect('database.db') as connection):
            cursor = connection.cursor()

            #extracting the current used security
            sec_method = os.getenv("SECURITY")
            print(sec_method)
            res = False
            #using the plain text for auth
            if sec_method == "plain":
                res = authenticate_plain(username, password,cursor)
            #using hashed password for auth
            elif sec_method == "hash":
                res = authenticate_hash(username, password,cursor)
            #using hash and salt for auth
            elif sec_method == "salt_and_hash":
                res = authenticate_hash_salt(username, password,cursor)
            #using hash salt and pepper for auth
            elif sec_method == "pepper_hash":
                res = authenticate_pepper(username, password,cursor)
            #using bcrypt for auth
            elif sec_method == "bcrypt":
                res = authenticate_bcrypt(username, password,cursor)
            #using argon2 for auth
            else:
                res = authenticate_argon2(username, password,cursor)


            # incorrect password
            if not res:
                return False,json.dumps({"status":"authentication failed"})

            #in case the Multi-factor authentication enabled
            if getenv("MFA_on"):
                temp_token = uuid.uuid4().hex
                totp_list[temp_token] =\
                    {"username": username,
                     "timeout":time.time()+120,
                     "attempts_left":5}
                return True,json.dumps({"status": "totp_required","MFA_token": temp_token})

            else:
                return True,json.dumps({"status":"authenticated"})


    finally:
        connection.close()

#gets a username password and cursor
#extracting the username's password and compares it to the given
def authenticate_plain(username, password,cursor):
    #extracting the password
    cursor.execute("SELECT password_plain FROM USERS WHERE username = ?", (username,))
    res = cursor.fetchone()
    #checking if there is no user with this username or the password is
    #incorrect
    if res is None or res[0] != password:
        return False
    return True

#gets a username password and cursor
#extracting the username's hashed_password and compares it to the given
#password hash
def authenticate_hash(username, password, cursor):
    #extracting the hashed password
    cursor.execute("SELECT password_hash FROM USERS WHERE username = ?", (username,))
    #hashing the given password
    password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    res = cursor.fetchone()
    #checking if the username exists and if the hashes match
    if res is None or res[0] != password:
        return False
    return True

#gets a username password and cursor
#extracting the username's hash_salted_password and compares it to the given
#password with the corresponding salt hash
def authenticate_hash_salt(username,password,cursor):

    #extracing the slat and the salted password hash from the db
    cursor.execute("SELECT salt, password_salt_hash FROM USERS WHERE username = ?", (username,))
    res = cursor.fetchone()
    #checks if username exists
    if res is None:
        return False
    #getting the salt from the db
    salt = res[0]
    #hashing the input password with the salt and comparing this with the one
    #on the db
    password = hashlib.sha256((password+salt).encode('utf-8')).hexdigest()
    if password == res[1]:
        return True
    return False

#gets a username password and cursor
#extracting the username's hash_pepper_password and compares it to the given
#password with the corresponding salt and pepper hash
def authenticate_pepper(username,password,cursor):
    #extrating the salt and the peppered hashed password from the db
    cursor.execute("SELECT salt,password_pepper_hash FROM USERS WHERE username = ?", (username,))
    res = cursor.fetchone()
    #checking if the user exists
    if res is None:
        return False

    #getting the salt and calculating the hash of the input password with
    #the salt and pepper
    salt = res[0]
    password = hashlib.sha256((password+salt+os.getenv("PEPPER")).encode('utf-8')).hexdigest()

    #checking if the hashes match
    if password == res[1]:
        return True
    return False

#gets a username password and cursor
#extracting the username's bcrypt password with the input password
def authenticate_bcrypt(username,password,cursor):
    #extracting the bcrypt hash
    cursor.execute("SELECT password_bcrypt FROM USERS WHERE username = ?", (username,))
    res = cursor.fetchone()

    #checking if the user exists
    if res is None:
        return False
    #comparing hashes
    if bcrypt.checkpw(password.encode("utf-8"), res[0]):
        return True
    return False

#gets a username password and cursor
#extracting the username's argon2 password with the input password
def authenticate_argon2(username,password,cursor):
    #extracting the user's argon2 hashes
    cursor.execute("SELECT password_argon2 FROM USERS WHERE username = ?", (username,))
    res = cursor.fetchone()

    #checking if the user exists
    if res is None:
        return False

    #comparing hashes
    if pass_hasher.verify(res[0], password):
        return True
    return False

#handling the totp authentication
def MFA_authenticate(MFA_token, MFA_code):

    #extracting the totp list
    totp_info = totp_list.get(MFA_token)
    #no temporary token exists -> no legal attempts left for totp
    if totp_info is None:
        return json.dumps({"status":"authentication failed"})

    #the temporary token used too late -> limit is two minutes from generation
    if(time.time() > totp_info["timeout"]):
        del totp_list[MFA_token]
        return json.dumps({"status": "timeout"})

    #too much attempts -> maximum attempts is 5
    if(totp_info["attempts_left"] <= 0):
        del totp_list[MFA_token]
        return json.dumps({"status": "authentication failed"})

    #legal attempt from here

    totp_info["attempts_left"] = totp_info["attempts_left"] - 1
    username = totp_info["username"]

    try:
        with (sqlite3.connect('database.db') as connection):
            cursor = connection.cursor()
            #extracting the user's secret
            cursor.execute("SELECT totp_secret FROM USERS WHERE username = ?",
                           (username,))
            res = cursor.fetchone()

            #user is not exists -> shouldn't happen but in case of data corruption
            if res is None:
                return json.dumps({"status": "authentication failed"})


            totp_secret = res[0]
            #secret is not exists -> could only happen in migration time
            if totp_secret is None:
                return json.dumps({"status":"error!","message":"no secret exists"})

            totp = pyotp.TOTP(totp_secret,digits=6,interval=30)

            #verifing totp
            if totp.verify(MFA_code,valid_window=1):
                del totp_list[MFA_token]
                return json.dumps({"status":"authenticated"})
            else:
                return json.dumps({"status":"authentication failed"})


    finally: connection.close()

