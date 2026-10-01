from flask import Flask, request
import sqlite3
import os

app = Flask(__name__)

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

if __name__ == '__main__':
    app.run(host='0.0.0.0')





