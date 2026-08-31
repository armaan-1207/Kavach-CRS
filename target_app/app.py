import os
import sqlite3
import subprocess
from flask import Flask, request

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

# Hardcoded credential - CWE-798
ADMIN_SECRET = "[REDACTED_SECRET]"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, role TEXT)")
    conn.execute("INSERT OR IGNORE INTO users (id, username, role) VALUES (1, 'admin', 'admin')")
    conn.commit()
    conn.close()

@app.route("/")
def index():
    return "Target App is running. Use /search, /ping, /read or /admin."

# Route 1: SQL Injection (CWE-89)
@app.route("/search")
def search():
    username = request.args.get("username", "")
    conn = sqlite3.connect(DB_PATH)
    # VULN: string interpolation directly into SQL query
    query = f"SELECT id, username FROM users WHERE username = '{username}'"
    cur = conn.execute(query)
    rows = cur.fetchall()
    conn.close()
    return {"results": rows}

# Route 2: Command Injection (CWE-78)
@app.route("/ping")
def ping():
    host = request.args.get("host", "8.8.8.8")
    # VULN: user input passed directly to shell
    import sys
    flag = "-n" if sys.platform == "win32" else "-c"
    result = subprocess.check_output(f"ping {flag} 1 {host}", shell=True, text=True)
    return result

# Route 3: Path Traversal (CWE-22)
@app.route("/read")
def read_file():
    filename = request.args.get("name", "readme.txt")
    base_dir = os.path.join(os.path.dirname(__file__), "data")
    # VULN: no path normalization, allows ../../../etc/passwd style traversal
    filepath = os.path.join(base_dir, filename)
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            return f.read()
    return "File not found.", 404

# Route 4: Hardcoded Secrets (CWE-798)
@app.route("/admin")
def admin():
    key = request.args.get("key", "")
    if key == ADMIN_SECRET:
        return "Admin access granted!"
    return "Access denied.", 403

if __name__ == "__main__":
    init_db()
    # VULN: debug mode enabled in production
    app.run(debug=True, port=5050)
