from flask import Flask, request
import ipaddress
import os
import re
import sqlite3
import subprocess

app = Flask(__name__)

def is_valid_host(host: str) -> bool:
    if not host or not isinstance(host, str) or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    hostname_regex = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    return bool(re.match(hostname_regex, host))

@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    return str(user)

@app.route('/ping')
def ping_host():
    host = request.args.get('host')
    if host:
        if not is_valid_host(host):
            return "Invalid host", 400
        subprocess.run(["ping", "-c", "1", "--", host])
    
    return "Ping command executed."

if __name__ == '__main__':
    app.run(host='0.0.0.0')
