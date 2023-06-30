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
            encrypted_msg NOT NULL,
            encrypted_cipher NOT NULL,
            FOREIGN KEY(sender) REFERENCES Users(username),
            FOREIGN KEY(receiver) REFERENCES Users(username));
        CREATE TABLE IF NOT EXISTS Groups(
            group_id VARCHAR(30) NOT NULL PRIMARY KEY,
            owner,
            FOREIGN KEY(owner) REFERENCES Users(username));
        CREATE TABLE IF NOT EXISTS Group_Members(
            group_id VARCHAR(30) NOT NULL,
            user_id NOT NULL,
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

    def insert_message(self, sender, receiver, encrypted_text_message, encrypted_cipher):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("INSERT INTO Messages(sender, receiver, encrypted_msg, encrypted_cipher) VALUES(?,?,?,?);", (sender, receiver, encrypted_text_message, encrypted_cipher,))
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
    
    def get_messages(self, receiver):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("SELECT encrypted_msg, encrypted_cipher FROM Messages WHERE receiver=?", (receiver,))
        rows = cur.fetchall()
        con.close()
        return rows
    
    def delete_messages(self, receiver):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute(f'DELETE FROM Messages WHERE receiver=?', (receiver,))
        con.commit()
        con.close()
        return True

    def has_group(self, group_id):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("SELECT group_id FROM Groups WHERE group_id=?", (group_id,))
        rows = cur.fetchall()
        con.close()
        return len(rows) > 0

    def is_member_of_group(self, user_id, group_id):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("SELECT * FROM Group_Members WHERE group_id=? and user_id=?", (group_id, user_id, ))
        rows = cur.fetchall()
        con.close()
        return len(rows) > 0

    def is_owner_of_group(self, user_id, group_id):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("SELECT group_id FROM Groups WHERE group_id=? and owner=?", (group_id, user_id, ))
        rows = cur.fetchall()
        con.close()
        return len(rows) > 0

    def insert_memeber(self, group_id, user_id):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute(
            "INSERT INTO Group_Members(group_id, user_id) VALUES(?,?);",
            (group_id, user_id,))
        con.commit()
        con.close()

    def delete_member(self, group_id, user_id):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute(f'DELETE FROM Group_Members WHERE group_id=? and user_id=?', (group_id, user_id,))
        con.commit()
        con.close()

    def insert_group(self, group_id, owner_id):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute(
            "INSERT INTO Groups(group_id, owner) VALUES(?,?);",
            (group_id, owner_id,))
        con.commit()
        con.close()

    def get_members(self, group_id):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("SELECT user_id FROM Group_Members WHERE group_id=?", (group_id,))
        rows = cur.fetchall()
        con.close()
        members = [row[0] for row in rows]
        return members

    def update_user(self, username, public_key):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("UPDATE Users SET public_key=? WHERE username=?", (public_key, username,))
        con.commit()
        con.close()
