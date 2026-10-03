import os
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/run', methods=['POST'])
def run_command():
    cmd = request.json.get('command')
    # Command injection: user input passed to shell
    output = subprocess.call(cmd, shell=True)
    return jsonify({"output": output})

@app.route('/ping', methods=['POST'])
def ping():
    host = request.json.get('host')
    # Command injection via f-string
    result = os.popen(f"ping -c 1 {host}").read()
    return jsonify({"result": result})
