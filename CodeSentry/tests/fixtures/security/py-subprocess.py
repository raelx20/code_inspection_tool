import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/convert', methods=['POST'])
def convert():
    filename = request.json.get('file')
    # subprocess with shell=True and user input
    subprocess.call(f"ffmpeg -i {filename} output.mp3", shell=True)
    return jsonify({"success": True})

@app.route('/process', methods=['POST'])
def process():
    data = request.json.get('data')
    # Another subprocess misuse
    result = subprocess.check_output(data, shell=True)
    return jsonify({"result": result.decode()})
