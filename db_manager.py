import sqlite3

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

def add_user(username, password):
    try:
        with sqlite3.connect('database.db') as connection:
            cursor = connection.cursor()
            cursor.execute("INSERT INTO USERS (username, password_plain) VALUES (?, ?)", (username, password))
            user_id = cursor.lastrowid
            cursor.execute("INSERT INTO USER_SPECS (user_id) VALUES (?) ", (user_id,))
            connection.commit()
        return "registered successfully"

    except sqlite3.IntegrityError:
        return "Username already in use."

    finally:
        connection.close()



def authenticate(username, password):
    try:
        with sqlite3.connect('database.db') as connection:
            cursor = connection.cursor()
            cursor.execute("SELECT password_plain FROM USERS WHERE username = ?", (username,))
            res = cursor.fetchone()
            if res is None or res[0] != password:
                return "Invalid username or password."

            return "True"

    finally:
        connection.close()


