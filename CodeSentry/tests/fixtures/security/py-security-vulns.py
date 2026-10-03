"""
Python Security Vulnerabilities Test Fixtures
"""
import os
import pickle
import subprocess
import sqlite3
import yaml
import tempfile
from flask import Flask, request, render_template_string, redirect, jsonify

app = Flask(__name__)

# ============ SQL INJECTION ============

@app.route('/user/<user_id>')
def get_user(user_id):
    # SQL Injection: string formatting
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)  # VULNERABLE
    return jsonify(cursor.fetchone())

@app.route('/search')
def search():
    term = request.args.get('q')
    # SQL Injection: concatenation
    query = "SELECT * FROM products WHERE name LIKE '%" + term + "%'"
    cursor.execute(query)  # VULNERABLE
    return jsonify(cursor.fetchall())

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    # SQL Injection: format string
    query = "SELECT * FROM users WHERE username='{}' AND password='{}'".format(username, password)
    cursor.execute(query)  # VULNERABLE
    return jsonify({"success": bool(cursor.fetchone())})

# ============ COMMAND INJECTION ============

@app.route('/ping')
def ping():
    host = request.args.get('host')
    # Command Injection: os.system
    result = os.system(f"ping -c 4 {host}")  # VULNERABLE
    return str(result)

@app.route('/execute')
def execute_cmd():
    cmd = request.args.get('cmd')
    # Command Injection: subprocess with shell=True
    output = subprocess.check_output(cmd, shell=True)  # VULNERABLE
    return output

@app.route('/run')
def run_command():
    user_input = request.args.get('input')
    # Command Injection: os.popen
    stream = os.popen(f"echo {user_input}")  # VULNERABLE
    return stream.read()

# ============ XSS (SERVER-SIDE) ============

@app.route('/greet')
def greet():
    name = request.args.get('name')
    # XSS: render_template_string with user input
    return render_template_string(f'<h1>Hello {name}!</h1>')  # VULNERABLE

@app.route('/search-results')
def search_results():
    query = request.args.get('q')
    # XSS: direct HTML response
    return f'<p>Results for: {query}</p>'  # VULNERABLE

# ============ INSECURE DESERIALIZATION ============

@app.route('/load-profile', methods=['POST'])
def load_profile():
    data = request.get_data()
    # Insecure Deserialization: pickle.loads
    profile = pickle.loads(data)  # VULNERABLE
    return jsonify(profile)

def load_object(data):
    # Pickle deserialization from untrusted source
    return pickle.loads(data)  # VULNERABLE

# ============ PATH TRAVERSAL ============

@app.route('/read-file')
def read_file():
    filename = request.args.get('file')
    # Path Traversal: no sanitization
    filepath = os.path.join('/data', filename)  # VULNERABLE
    with open(filepath, 'r') as f:
        return f.read()

@app.route('/download')
def download():
    path = request.args.get('path')
    # Path Traversal: direct user input
    return send_file(path)  # VULNERABLE

# ============ YAML DESERIALIZATION ============

@app.route('/config', methods=['POST'])
def load_config():
    config_data = request.get_data().decode()
    # YAML Deserialization: yaml.load with full Loader
    config = yaml.load(config_data, Loader=yaml.FullLoader)  # VULNERABLE
    return jsonify(config)

def parse_yaml(data):
    # Unsafe YAML loading
    return yaml.load(data)  # VULNERABLE

# ============ INSECURE TEMP FILE ============

def create_temp_file(data):
    # Insecure Temp File: predictable name
    tmp_path = '/tmp/app_' + data + '.txt'  # VULNERABLE
    with open(tmp_path, 'w') as f:
        f.write(data)
    return tmp_path

def create_temp_secure():
    # Better: use tempfile module
    fd, path = tempfile.mkstemp()
    return path

# ============ HARDCODED SECRETS ============

AWS_ACCESS_KEY = "YOUR_AWS_ACCESS_KEY"
AWS_SECRET_KEY = "YOUR_AWS_SECRET_KEY"
DATABASE_PASSWORD = "YOUR_DB_PASSWORD"
SECRET_KEY = "YOUR_SECRET_KEY"

# ============ LDAP INJECTION ============

def ldap_search(username):
    import ldap
    # LDAP Injection
    filter_str = f"(uid={username})"  # VULNERABLE
    result = ldap.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, filter_str)
    return result

# ============ XML EXTERNAL ENTITY (XXE) ============

def parse_xml(xml_data):
    from xml.etree import ElementTree
    # XXE: no defusedxml
    tree = ElementTree.fromstring(xml_data)  # VULNERABLE
    return tree

# ============ INSECURE RANDOM ============

import random

def generate_token():
    # Insecure: not cryptographically secure
    return ''.join([chr(random.randint(65, 90)) for _ in range(32)])  # VULNERABLE

def generate_otp():
    # Better: use secrets module
    import secrets
    return ''.join([str(secrets.randbelow(10)) for _ in range(6)])

# ============ WEAK CRYPTO ============

import hashlib

def hash_password_weak(password):
    # Weak: MD5 without salt
    return hashlib.md5(password.encode()).hexdigest()  # VULNERABLE

def hash_password_sha1(password):
    # Weak: SHA1 without salt
    return hashlib.sha1(password.encode()).hexdigest()  # VULNERABLE

def verify_password(input_pwd, stored_hash):
    # Weak: no constant-time comparison
    return hashlib.md5(input_pwd.encode()).hexdigest() == stored_hash  # VULNERABLE

if __name__ == '__main__':
    app.run(debug=True)  # DEBUG mode in production
