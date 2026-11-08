import sqlite3, subprocess, hashlib, os, secrets

DB = sqlite3.connect("app.db")

def run_query(sql, params=()):
    cur = DB.cursor()
    cur.execute(sql, params)
    return cur.fetchall()

def get_user(name):
    return run_query("SELECT * FROM users WHERE name = ?", (name,))

def ping(host):
    if not host.replace(".", "").replace("-", "").isalnum():
        raise ValueError("bad host")
    return subprocess.call(["ping", "-c1", host])

def store_password(pw):
    salt = secrets.token_bytes(16)
    return salt.hex() + hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1).hex()

def read_file(path):
    base = os.path.realpath("/srv/files")
    full = os.path.realpath(os.path.join(base, path))
    if os.path.commonpath([base, full]) != base:
        raise PermissionError("path escape")
    return open(full).read()
