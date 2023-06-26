import sqlite3
from sqlite3 import Error


class Database:
    def __init__(self):
        self.db_path = "database.db"
        print('SQLite Version:', sqlite3.version)
        self.create_tables()
    
    def create_tables(self):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS users(username PRIMARY KEY, h_password, public_key, salt)")
        con.close()
    
    def insert_user(self, username, h_password, public_key='', salt=''):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("INSERT INTO users(username, h_password, public_key, salt) VALUES(?,?,?,?);", (username, h_password, public_key, salt,))
        con.commit()
        con.close()
    
    def has_user(self, username):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("SELECT username FROM users WHERE username=?", (username,))
        rows = cur.fetchall()
        con.close()
        return len(rows) > 0
    
    def check_password(self, username, h_password):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("SELECT h_password FROM users WHERE username=?", (username,))
        rows = cur.fetchall()
        if len(rows) == 0:
            return False
        real_h_password = rows[0][0]
        con.close()
        return h_password == real_h_password
