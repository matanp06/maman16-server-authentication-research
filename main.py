from flask import Flask, render_template
import os

project_root = os.path.dirname(os.path.abspath(__file__))
# template_path = os.path.join(project_root, './')

app = Flask(__name__, template_folder=project_root)

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/login")
def login():
    return render_template('login.html')

@app.route("/register")
def register():
    return render_template('register.html')

if __name__ == "__main__":
    app.run()