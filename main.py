import json
import time

from flask import Flask, render_template,request
import os

import captcha_manager
import db_manager
from db_manager import config_db
from dotenv import load_dotenv

load_dotenv()

project_root = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, template_folder=project_root)

#extracting request data
def ext_data(req):
    if req.is_json:
        data = req.get_json()
    else:
        data = req.form
    return data

#Main route -> HOME PAGE
@app.route("/")
def index():
    return render_template('index.html')

#Login page
@app.route("/login", methods=['GET'])
def login():
    return render_template('login.html')

#Login request
@app.route("/login", methods=['POST'])
def authenticate():

    # extracting data
    data = ext_data(request)

    # extracting username and password
    username = data.get('username')
    password = data.get('password')
    secret = data.get('secret')
    captcha_token = data.get('captcha_token')
    is_captcha_on=os.getenv('CAPTCHA_ON')
    user_ip = request.remote_addr

    #handle captcha
    if is_captcha_on and captcha_manager.captcha_required(user_ip):
        if captcha_token is None:
            return json.dumps({"status": "failed","reason":"captcha token is required"})
        captcha_test_res,message = captcha_manager.validate_captcha_code(user_ip,captcha_token)
        if not captcha_test_res:
            return message


    #dismissing empty values
    if len(username) == 0 or len(password) == 0:
        return "Invalid username or password."

    login_res,ret_json =db_manager.authenticate(username, password)
    if is_captcha_on:
        if not login_res:
            captcha_manager.update_password_failed_attempts(user_ip)
        else:
            captcha_manager.update_successful_login_attempts(user_ip)

    return ret_json


@app.route("/login_totp",methods=['POST'])
def login_totp():
    data = ext_data(request)
    MFA_token = data.get('MFA_token')
    MFA_code = data.get('MFA_code')
    return db_manager.MFA_authenticate(MFA_token, MFA_code)

#Register page
@app.route("/register",methods=['GET'])
def register():
    return render_template('register.html')

#Register request
@app.route("/register", methods=['POST'])
def add_user():

    #extracting data
    data =ext_data(request)

    #extracting username and password
    username = data.get('username')
    password = data.get('password')

    #checking for legality
    if len(username) == 0 or len(password) == 0:
        return "Missing username or password."

    return db_manager.add_user(username, password)

#the captcha solving path
@app.route("/admin/get_captcha_token", methods=['GET'])
def admin_get_captcha_token():
    #extracting required parameters
    tested_group_seed = request.args.get('group_seed')
    user_ip = request.remote_addr

    #generating captcha answer
    return captcha_manager.captcha_gen(user_ip,tested_group_seed)


if __name__ == "__main__":
    config_db()
    app.run(debug=True)



