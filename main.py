import json
import time

from flask import Flask, render_template,request
import os

import captcha_manager
import db_manager
import log_manager
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

    start_time = time.time()
    # extracting data
    data = ext_data(request)

    # extracting username and password
    username = data.get('username')
    password = data.get('password')
    secret = data.get('secret')
    captcha_token = data.get('captcha_token')
    is_captcha_on=os.getenv('CAPTCHA_ON')
    user_ip = request.remote_addr

    #debug
    print(json.dumps({
        'username': username,
        'password': password,
        'secret': secret,
        'captcha_token':captcha_token
    }))


    #handle captcha
    if is_captcha_on == "True" and captcha_manager.captcha_required(user_ip):
        if captcha_token is None:
            res_json = json.dumps({"status": "failed","reason":"captcha token is required"})
            log_manager.write_log(username,start_time,request.path,403,res_json)
            return res_json,403
        captcha_test_res,res_json = captcha_manager.validate_captcha_code(user_ip,captcha_token)
        if not captcha_test_res:
            log_manager.write_log(username, start_time, request.path, 403,res_json )
            return res_json,403


    #dismissing empty values
    if len(username) == 0 or len(password) == 0:
        res_json = json.dumps({"status": "failed","reason":"username or password is empty"})
        log_manager.write_log(username,start_time,request.path,403,res_json)
        return res_json,403

    login_res,ret_json =db_manager.authenticate(username, password)
    print(login_res,ret_json)
    if is_captcha_on == "True":
        if not login_res:
            captcha_manager.update_password_failed_attempts(user_ip)
        else:
            captcha_manager.update_successful_login_attempts(user_ip)

    reason = json.loads(ret_json).get('reason')
    if login_res:
        status_code = 200
    elif reason is not None and reason == "user locked":
        status_code = 403
    else:
        status_code = 401

    log_manager.write_log(username,start_time,request.path,status_code,ret_json)
    return ret_json, status_code


@app.route("/login_totp",methods=['POST'])
def login_totp():
    start_time = time.time()
    data = ext_data(request)
    MFA_token = data.get('MFA_token')
    MFA_code = data.get('MFA_code')
    print("MFA_code",MFA_code)
    login_res,ret_json,username = db_manager.MFA_authenticate(MFA_token, MFA_code)
    status = 200 if login_res==True else 401
    log_manager.write_log(username,start_time,request.path,status,ret_json)
    return ret_json, status

#Register page
@app.route("/register",methods=['GET'])
def register():
    return render_template('register.html')

#Register request
@app.route("/register", methods=['POST'])
def add_user():

    start_time = time.time()

    #extracting data
    data =ext_data(request)

    #extracting username and password
    username = data.get('username')
    password = data.get('password')
    secret = data.get('secret')#for debug perpuse only

    #checking for legality
    if len(username) == 0 or len(password) == 0:
        return "Missing username or password."

    register_res,ret_json =  db_manager.add_user(username, password,secret)
    status = 200 if register_res==True else 401
    log_manager.write_log(username,start_time,"/register",status,ret_json)
    return ret_json, status

#the captcha solving path
@app.route("/admin/get_captcha_token", methods=['GET'])
def admin_get_captcha_token():

    start_time = time.time()
    #extracting required parameters
    tested_group_seed = request.args.get('group_seed')
    user_ip = request.remote_addr

    #generating captcha answer
    print(captcha_manager.captcha_gen(user_ip,tested_group_seed))
    captcha_res,ret_json = captcha_manager.captcha_gen(user_ip,tested_group_seed)
    status = (200 if captcha_res==True else 403)
    log_manager.write_log(username=request.remote_addr,start_time=start_time,route=request.path,status=status,res_json=ret_json)
    return ret_json, status


if __name__ == "__main__":
    config_db()
    log_manager.setup()
    app.run(debug=False)



