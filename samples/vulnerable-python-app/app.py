import sqlite3
import psycopg2
from flask import Flask, request, jsonify

app = Flask(__name__)

DB_SECRET_PASS = "postgres://admin:SuperSecret2026!@10.0.0.5:5432/appdb"

def get_db_connection():
    return sqlite3.connect(':memory:')

# Vulnerable Endpoint 1: Python f-string interpolation in sqlite3 cursor.execute
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # CRITICAL SQL INJECTION: Unsanitized form input in f-string query
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        return jsonify({"status": "success", "user": user[1]})
    return jsonify({"status": "failed"}), 401

# Vulnerable Endpoint 2: Percent formatting string operator
@app.route('/items', methods=['GET'])
def get_items():
    category = request.args.get('category')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # HIGH SQL INJECTION: String percent formatting in raw SQL statement
    sql = "SELECT id, item_name, price FROM inventory WHERE category = '%s'" % category
    cursor.execute(sql)
    items = cursor.fetchall()
    
    return jsonify({"items": items})

# Safe Endpoint: Parameterized tuple binding in sqlite3
@app.route('/safe-login', methods=['POST'])
def safe_login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # SECURE: Parameterized positional tuple query
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = cursor.fetchone()
    
    return jsonify({"status": "safe_check"})

if __name__ == '__main__':
    app.run(port=5000)
