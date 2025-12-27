import json

from flask import Flask, render_template,request
import os

project_root = os.path.dirname(os.path.abspath(__file__))
# template_path = os.path.join(project_root, './')

app = Flask(__name__, template_folder=project_root)

#extracting request data
def ext_data(req):
    if req.is_json:
        data = req.get_json()
    else:
        data = req.form
    return data

#temporery database
users = [{"id": 1,"username": "user1", "password": "1234"},
         {"id": 2,"username": "user2", "password": "4444"},
         {"id": 3,"username": "user3", "password": "5555"}]

nextID = users[-1]["id"]+1

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
    print(username, password)
    #checks for now for username and password match only
    if any(u["username"] == username and u["password"] == password for u in users):
        return "True"
    else:
        return "False"

#Register page
@app.route("/register",methods=['GET'])
def register():
    return render_template('register.html')

#Register request
@app.route("/register", methods=['POST'])
def add_user():
    global nextID

    print("im here")
    #extracting data
    data =ext_data(request)

    #extracting username and password
    username = data.get('username')
    password = data.get('password')

    #checking for legality
    if len(username) == 0 or len(password) == 0:
        return "Missing username or password."

    #checking for username uniqueness
    if any (u["username"] == username for u in users):
        return "Username already registered"
    else:
        users.append({"id": nextID, "username": username, "password": password})
        nextID += 1
        return "Cool"





if __name__ == "__main__":
    app.run(debug=True)



