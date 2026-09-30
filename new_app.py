from flask import Flask, request
import sqlite3
import os

app = Flask(__name__)

API_KEY = os.environ.get("API_KEY", "default_dev_key")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "default_dev_password")

@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    
    user = cursor.fetchone()
    return str(user)

@app.route('/ping')
def ping_host():
    host = request.args.get('host')
    
    os.system(f"ping -c 1 {host}")
    
    return "Ping command executed."

@app.route('/read_file')
def read_file():
    filename = request.args.get('file', '')
    
    base_dir = os.path.abspath("/var/www/uploads")
    file_path = os.path.abspath(os.path.join(base_dir, filename.lstrip('/')))
    
    if not file_path.startswith(base_dir + os.sep):
        return "Access denied", 403
        
    with open(file_path, 'r') as f:
        content = f.read()
        
    return content

@app.route('/hello')
def hello():
    name = request.args.get('name', 'Guest')
    
    return f"<h1>Hello, {name}!</h1>"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
