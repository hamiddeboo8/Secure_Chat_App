import sqlite3
from sqlite3 import Error
import time


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
            sender,
            receiver,
            group_id,
            encrypted_msg NOT NULL,
            encrypted_cipher NOT NULL,
            FOREIGN KEY(sender) REFERENCES Users(username),
            FOREIGN KEY(receiver) REFERENCES Users(username),
            FOREIGN KEY(group_id) REFERENCES Groups(group_id));
        CREATE TABLE IF NOT EXISTS Groups(
            group_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            owner,
            FOREIGN KEY(owner) REFERENCES Users(username));
        CREATE TABLE IF NOT EXISTS Group_Members(
            group_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            PRIMARY KEY (group_id, user_id),
            FOREIGN KEY(user_id) REFERENCES Users(username),
            FOREIGN KEY(group_id) REFERENCES Groups(group_id));
        
        '''
        cur.executescript(sql)
        con.close()
    
    def insert_user(self, username, h_password, public_key='', salt=''):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("INSERT INTO Users(username, h_password, public_key, salt) VALUES(?,?,?,?);", (username, h_password, public_key, salt,))
        con.commit()
        con.close()

    def insert_message(self, sender, receiver, encrypted_text_message, encrypted_cipher, group_id=None):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("INSERT INTO Messages(sender, receiver, group_id, encrypted_msg, encrypted_cipher) VALUES(?,?,?,?,?);", (sender, receiver, group_id, encrypted_text_message, encrypted_cipher,))
        con.commit()
        con.close()
    
    def has_user(self, username):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("SELECT username FROM Users WHERE username=?", (username,))
        rows = cur.fetchall()
        con.close()
        return len(rows) > 0

    def get_public_key(self, username):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("SELECT public_key FROM Users WHERE username=?", (username,))
        rows = cur.fetchall()
        if len(rows) == 0:
            return False
        con.close()
        return rows[0][0]
    
    def get_salt(self, username):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("SELECT salt FROM Users WHERE username=?", (username,))
        rows = cur.fetchall()
        if len(rows) == 0:
            return False
        con.close()
        return rows[0][0]
    
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
    
    def get_password(self, username):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("SELECT h_password FROM Users WHERE username=?", (username,))
        rows = cur.fetchall()
        if len(rows) == 0:
            return False
        con.close()
        return rows[0][0]
