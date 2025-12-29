from flask import Flask, render_template,request
import os

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

    #dismissing empty values
    if len(username) == 0 or len(password) == 0:
        return "Invalid username or password."

    return db_manager.authenticate(username, password)

    #checks for now for username and password match only


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


if __name__ == "__main__":
    config_db()
    app.run(debug=True)



