import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/user/<user_id>')
def get_user(user_id):
    # SQL injection: f-string directly in query
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    result = db.execute(query)
    return jsonify(result)

@app.route('/search')
def search():
    term = request.args.get('q')
    # SQL injection via string concatenation
    sql = "SELECT * FROM products WHERE name LIKE '%" + term + "%'"
    rows = db.execute(sql)
    return jsonify(rows)
