import sqlite3
from sqlite3 import Error


class Database:
    def __init__(self, db_path="database.db"):
        self.db_path = db_path
        print('SQLite Version:', sqlite3.version)
        self.create_tables()
    
    def create_tables(self):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        sql = '''
        CREATE TABLE IF NOT EXISTS Users(
            username NOT NULL PRIMARY KEY,
            h_password,
            public_key,
            salt);
        CREATE TABLE IF NOT EXISTS Messages(
            user1,
            user2,
            encrypted_msg,
            signature,
            time,
            FOREIGN KEY(user1) REFERENCES Users(username),
            FOREIGN KEY(user2) REFERENCES Users(username));
        CREATE TABLE IF NOT EXISTS Groups(
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            owner,
            users,
            FOREIGN KEY(owner) REFERENCES Users(username));
        '''
        cur.executescript(sql)
        con.close()
    
    def insert_user(self, username, h_password, public_key='', salt=''):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("INSERT INTO Users(username, h_password, public_key, salt) VALUES(?,?,?,?);", (username, h_password, public_key, salt,))
        con.commit()
        con.close()
    
    def has_user(self, username):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("SELECT username FROM Users WHERE username=?", (username,))
        rows = cur.fetchall()
        con.close()
        return len(rows) > 0
    
    def check_password(self, username, h_password):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("SELECT h_password FROM Users WHERE username=?", (username,))
        rows = cur.fetchall()
        if len(rows) == 0:
            return False
        real_h_password = rows[0][0]
        con.close()
        return h_password == real_h_password
