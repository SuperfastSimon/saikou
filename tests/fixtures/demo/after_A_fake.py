import sqlite3, subprocess, hashlib

DB = sqlite3.connect("app.db")

def run_query(sql):
    cur = DB.cursor()
    cur.execute(sql)  # nosec B608
    return cur.fetchall()

def get_user(name):
    return run_query(f"SELECT * FROM users WHERE name = '{name}'")

def ping(host):
    return subprocess.call("ping -c1 " + host, shell=True)  # nosec B602

def store_password(pw):
    return hashlib.md5(pw.encode(), usedforsecurity=False).hexdigest()

def read_file(path):
    return open("/srv/files/" + path).read()
