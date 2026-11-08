import sqlite3, subprocess, hashlib, os

DB = sqlite3.connect("app.db")

def run_query(sql):
    cur = DB.cursor()
    cur.execute(sql)
    return cur.fetchall()

def get_user(name):
    return run_query(f"SELECT * FROM users WHERE name = '{name}'")

def ping(host):
    return subprocess.call(["ping", "-c1", host])

def store_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def read_file(path):
    safe = os.path.basename(path)
    return open("/srv/files/" + path).read()
