"""
Kavach-CRS Demo Target App
Deliberately vulnerable Flask application with 4 seeded vulnerabilities.
DO NOT deploy this in any real environment.
"""
import sqlite3
import os
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

# Hardcoded credential -- CWE-798
ADMIN_SECRET = "s3cr3t_admin_key_2024"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    conn.execute("INSERT OR IGNORE INTO users VALUES (1, 'alice', 'pass123')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2, 'bob', 'qwerty')")
    conn.commit()
    conn.close()


# --- VULN 1: SQL Injection (CWE-89) ---
@app.route("/user")
def get_user():
    """Look up a user by username. Vulnerable to SQL injection."""
    username = request.args.get("username", "")
    conn = sqlite3.connect(DB_PATH)
    # VULN: string interpolation directly into SQL query
    query = f"SELECT id, username FROM users WHERE username = '{username}'"
    cur = conn.execute(query)
    rows = cur.fetchall()
    conn.close()
    return jsonify(rows)


# --- VULN 2: Command Injection (CWE-78) ---
@app.route("/ping")
def ping_host():
    """Ping a host. Vulnerable to command injection."""
    host = request.args.get("host", "127.0.0.1")
    # VULN: user input passed directly to shell
    # KAVACH-PATCH: list-based subprocess, no shell (CWE-78 fix)
    result = subprocess.check_output(["ping", "-n", "1", host], text=True)
    return result


# --- VULN 3: Path Traversal (CWE-22) ---
@app.route("/file")
def read_file():
    """Read a file from the data directory. Vulnerable to path traversal."""
    filename = request.args.get("name", "readme.txt")
    base_dir = os.path.join(os.path.dirname(__file__), "data")
    # VULN: no path normalization, allows ../../../etc/passwd style traversal
    # KAVACH-PATCH: path normalisation + containment check (CWE-22 fix)
    filepath = os.path.realpath(os.path.join(base_dir, filename))
    if not filepath.startswith(os.path.realpath(base_dir)):
        return 'Access denied', 403
    try:
        with open(filepath, "r") as f:
            return f.read()
    except FileNotFoundError:
        return "File not found", 404


# --- VULN 4: Hardcoded Credential used in auth check (CWE-798) ---
@app.route("/admin")
def admin_panel():
    """Admin panel protected by hardcoded secret."""
    key = request.args.get("key", "")
    # VULN: secret is hardcoded in source, not from env
    if key == ADMIN_SECRET:
        return jsonify({"status": "ok", "message": "Welcome, admin!"})
    return jsonify({"status": "denied"}), 403


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5050)
