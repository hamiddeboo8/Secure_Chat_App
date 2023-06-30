import hashlib
import json
import os
import socket
import threading

from parse import parse
from .database import Database
from utils.utils import *


class Server:
    def __init__(self):
        self.MAX_LENGTH = 65536
        self.PORT = 5050
        self.SERVER = socket.gethostbyname(socket.gethostname())
        self.ADDR = (self.SERVER, self.PORT)
        self.FORMAT = 'latin-1'
        self.DISCONNECT_MESSAGE = "!DISCONNECT"

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(self.ADDR)

        if not os.path.isfile('server-keys.pem'):
            self.private_key, self.public_key = set_keys()
            save_server_keys(self.private_key, self.public_key)
        else:
            self.private_key, self.public_key = load_server_keys()
        print('Server public key found')
        self.database = Database()

        self.lock = threading.Lock()  # lock for users dict
        self.users = {}  # token -> (username, conn, addr) TODO: change maybe

    def get_msg(self, conn, addr):
        try:
            msg = conn.recv(self.MAX_LENGTH)
            return msg
        except:
            print(f"[UNEXPECTED CLOSE CONNECTION] {addr}")
            exit(-1)

    def send_msg(self, msg, conn, addr):
        conn.send(msg)

    def handshake(self, conn, addr):
        try:
            cipher_text = self.get_msg(conn, addr)
            plain = asymmetric_decrypt(cipher_text, self.private_key)
            plain = plain.decode(self.FORMAT)
            plain = json.loads(plain)
            msg = plain['message']
            session_key, session_iv, nonce = msg['session_key'].encode(self.FORMAT), msg['session_iv'].encode(
                self.FORMAT), msg['nonce']
            cipher = get_cipher(session_key, session_iv)
            response = json.dumps({'status': '', 'message': '', 'nonce': nonce})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
        except:
            print(f"[UNEXPECTED CLOSE CONNECTION] {addr}")
            exit(-1)

        return cipher

    def handle_client(self, conn, addr):
        cipher = self.handshake(conn, addr)
        print(f"[NEW CONNECTION] {addr} connected.")
        connected = True
        while connected:
            msg = self.get_msg(conn, addr)
            msg = json.loads(symmetric_decrypt(msg, cipher).decode(self.FORMAT))
            msg_json, signature = msg['message'], msg['signature']

            msg_command = msg_json['command']
            if msg_command == self.DISCONNECT_MESSAGE:
                connected = False
                continue
            elif msg_command == 'REGISTER':
                self.register(msg_json, signature, conn, addr, cipher)
            elif msg_command == 'LOGIN':
                self.login(msg_json, signature, conn, addr, cipher)
            elif msg_command == 'LOGOUT':
                self.logout(msg_json, signature, conn, addr, cipher)
            elif msg_command == 'DIRECT':
                self.direct(msg_json, signature, conn, addr, cipher)
            elif msg_command == 'UPDATE':
                self.update(msg_json, signature, conn, addr, cipher)
            elif msg_command == 'ONLINE_USERS':
                self.send_online_users(msg_json, signature, conn, addr, cipher)
            elif msg_command == 'ADD_MEMBER':
                self.add_member(msg_json, signature, conn, addr, cipher)
            elif msg_command == 'DELETE_MEMBER':
                self.delete_member(msg_json, signature, conn, addr, cipher)
            elif msg_command == 'GROUP_MESSAGE':
                self.group_message(msg_json, signature, conn, addr, cipher)
            elif msg_command == 'CREATE_GROUP':
                self.create_group(msg_json, signature, conn, addr, cipher)
            elif msg_command == 'RENEW_KEY':
                cipher = self.renew_keys(msg_json, signature, conn, addr, cipher)
            else:
                print('Invalid msg - ignored')
        print(f"[CLOSE CONNECTION] {addr} closed.")

    def start(self):
        self.server.listen()
        print(f"[LISTENING] Server is listening on {self.SERVER}")
        while True:
            conn, addr = self.server.accept()
            thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            thread.start()
            print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")

    def register(self, msg_json, signature, conn, addr, cipher):
        username = msg_json['username']
        password = msg_json['password']
        nonce = msg_json['nonce']
        public_key = deserialize_public_key(msg_json['public_key'].encode(self.FORMAT))
        if not verify(json.dumps(msg_json).encode(self.FORMAT), signature.encode(self.FORMAT), public_key):
            print(f"[UNEXPECTED CLOSE CONNECTION]")
            exit(-1)

        save_status, msg = self.save_user(username, password, msg_json['public_key'])
        message = {'status': save_status, 'message': msg, 'nonce': nonce}
        signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
        response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
        self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)

    def save_user(self, username, password, public_key):
        if self.database.has_user(username):
            return False, 'USERNAME ALREADY EXISTS'
        salt = int.from_bytes(os.urandom(8), byteorder="big")
        salt = str(salt)
        salty_password = f'{password}_{salt}'
        h_password = hashlib.sha256(salty_password.encode(self.FORMAT)).hexdigest()
        self.database.insert_user(username=username, h_password=h_password, public_key=public_key, salt=salt)
        return True, 'REGISTER SUCCESSFUL'

    def update_user(self, username, password, public_key):
        if not self.database.has_user(username):
            return False, 'USERNAME DOES NOT EXIST'
        salt = self.database.get_salt(username)
        salty_password = f'{password}_{salt}'
        h_password = hashlib.sha256(salty_password.encode(self.FORMAT)).hexdigest()
        if not self.database.check_password(username, h_password):
            return False, 'PASSWORD WRONG!'

        self.database.update_user(username=username, public_key=public_key)
        return True, 'UPDATE SUCCESSFUL'

    def logout(self, msg_json, signature, conn, addr, cipher):
        token = msg_json['token']
        username = self.users[token][0]
        public_key = deserialize_public_key(self.database.get_public_key(username).encode(self.FORMAT))
        if not verify(json.dumps(msg_json).encode(self.FORMAT), signature.encode(self.FORMAT), public_key):
            print(f"[UNEXPECTED CLOSE CONNECTION]")
            exit(-1)
        self.users.pop(token)

    def send_online_users(self, msg_json, signature, conn, addr, cipher):
        token = msg_json['token']
        nonce = msg_json['nonce']
        users = set()
        for user in self.users.items():
            users.add(user[1][0])
        users = list(users)
        message = {'status': True, 'message': 'OK', 'nonce': nonce, 'users': users}
        signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
        response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
        self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)

    def is_logged_in(self, username):
        for user in list(self.users.values()):
            if user[0] == username:
                return True
        return False

    def login(self, msg_json, signature, conn, addr, cipher):
        nonce1 = msg_json['nonce']
        username = msg_json['username']
        if not self.database.has_user(username):
            message = {'status': False, 'message': 'USERNAME NOT FOUND', 'nonce': None, 'salt': None}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return
        if self.is_logged_in(username):
            message = {'status': False, 'message': 'LOGGED IN ALREADY!', 'nonce': None, 'salt': None}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return
        salt = self.database.get_salt(username)
        public_key = deserialize_public_key(self.database.get_public_key(username).encode(self.FORMAT))
        if not verify(json.dumps(msg_json).encode(self.FORMAT), signature.encode(self.FORMAT), public_key):
            message = {'status': False, 'message': 'NOT VERIFIED', 'nonce': None, 'salt': None}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return

        nonce2 = int.from_bytes(os.urandom(16), byteorder="big")
        message = {'status': True, 'message': 'OK', 'nonce': nonce2, 'salt': salt}
        signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
        response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
        self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)

        msg = self.get_msg(conn, addr)
        msg = json.loads(symmetric_decrypt(msg, cipher).decode(self.FORMAT))
        msg_json, signature = msg['message'], msg['signature']
        hh_password = msg_json['hh_password']
        h_password = self.database.get_password(username)
        nh_password = f'{h_password}_{nonce2}'
        real_hh_password = hashlib.sha256(nh_password.encode(self.FORMAT)).hexdigest()
        if hh_password != real_hh_password:
            message = {'status': False, 'message': 'WRONG PASSWORD', 'nonce': nonce1}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return
        token = int.from_bytes(os.urandom(16), byteorder="big")
        message = {'token': token, 'status': True, 'message': 'OK', 'nonce': nonce1}
        signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
        response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
        self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)

        with self.lock:
            self.users[token] = (username, conn, addr)

    def direct(self, msg_json, signature, conn, addr, cipher):
        nonce1 = msg_json['nonce']
        target_username = msg_json['target_username']
        token = msg_json['token']

        username = self.users[token][0]
        public_key = deserialize_public_key(self.database.get_public_key(username).encode(self.FORMAT))
        if not verify(json.dumps(msg_json).encode(self.FORMAT), signature.encode(self.FORMAT), public_key):
            message = {'status': False, 'message': 'NOT VERIFIED', 'nonce': nonce1, 'target_public_key': None}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return

        if not self.database.has_user(target_username):
            message = {'status': False, 'message': 'USERNAME NOT FOUND', 'nonce': nonce1, 'target_public_key': None}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return

        target_public_key = self.database.get_public_key(target_username)

        message = {'status': True, 'message': 'OK', 'nonce': nonce1, 'target_public_key': target_public_key}
        signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
        response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
        self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)

        msg = self.get_msg(conn, addr)
        msg = json.loads(symmetric_decrypt(msg, cipher).decode(self.FORMAT))
        msg_json, signature = msg['message'], msg['signature']

        if not verify(json.dumps(msg_json).encode(self.FORMAT), signature.encode(self.FORMAT), public_key):
            message = {'status': False, 'message': 'NOT VERIFIED', 'nonce': nonce1}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return

        nonce2 = msg_json['nonce']
        encrypted_text_message = msg_json['encrypted_text_message']
        encrypted_cipher = msg_json['encrypted_cipher']

        self.database.insert_message(username, target_username, encrypted_text_message, encrypted_cipher)

        message = {'status': True, 'message': 'OK', 'nonce': nonce2}
        signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
        response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
        self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)

    def update(self, msg_json, signature, conn, addr, cipher):
        nonce1 = msg_json['nonce']
        token = msg_json['token']

        if token not in self.users:
            message = {'status': False, 'message': 'NOT VERIFIED TOKEN', 'nonce': nonce1}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return

        username = self.users[token][0]
        public_key = deserialize_public_key(self.database.get_public_key(username).encode(self.FORMAT))
        if not verify(json.dumps(msg_json).encode(self.FORMAT), signature.encode(self.FORMAT), public_key):
            message = {'status': False, 'message': 'NOT VERIFIED', 'nonce': nonce1}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return

        updated_messages = self.database.get_messages(username)

        nonce2 = int.from_bytes(os.urandom(16), byteorder="big")
        message = {'status': True, 'message': 'SUCCESSFULLY UPDATED',
                   'updated_messages': updated_messages, 'nonce': nonce1, 'nonce2': nonce2}
        signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
        response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
        self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)

        msg = self.get_msg(conn, addr)
        msg = json.loads(symmetric_decrypt(msg, cipher).decode(self.FORMAT))
        msg_json, signature = msg['message'], msg['signature']

        if not verify(json.dumps(msg_json).encode(self.FORMAT), signature.encode(self.FORMAT), public_key):
            return

        if not nonce2 == msg_json['nonce']:
            return

        self.database.delete_messages(username)

    def add_member(self, msg_json, signature, conn, addr, cipher):
        nonce = msg_json['nonce']
        token = msg_json['token']

        if token not in self.users:
            message = {'status': False, 'message': 'NOT VERIFIED TOKEN', 'nonce': nonce}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return

        username = self.users[token][0]
        public_key = deserialize_public_key(self.database.get_public_key(username).encode(self.FORMAT))
        if not verify(json.dumps(msg_json).encode(self.FORMAT), signature.encode(self.FORMAT), public_key):
            message = {'status': False, 'message': 'NOT VERIFIED', 'nonce': nonce}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return

        group_id = msg_json['group_id']
        if not self.database.has_group(group_id):
            message = {'status': False, 'message': 'GROUP NOT FOUND!', 'nonce': nonce}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return

        target_username = msg_json['username']
        if not self.database.has_user(target_username):
            message = {'status': False, 'message': 'USER NOT FOUND!', 'nonce': nonce}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return

        if self.database.is_member_of_group(target_username, group_id):
            message = {'status': False, 'message': 'USER IS MEMBER OF THE GROUP!', 'nonce': nonce}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return

        if not self.database.is_owner_of_group(username, group_id):
            message = {'status': False, 'message': 'ONLY OWNER CAN ADD MEMBERS!', 'nonce': nonce}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return
        self.database.insert_memeber(group_id, target_username)

        message = {'status': True, 'message': 'SUCCESSFULLY INSERTED!', 'nonce': nonce}
        signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
        response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
        self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)

    def delete_member(self, msg_json, signature, conn, addr, cipher):
        nonce = msg_json['nonce']
        token = msg_json['token']

        if token not in self.users:
            message = {'status': False, 'message': 'NOT VERIFIED TOKEN', 'nonce': nonce}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return

        username = self.users[token][0]
        public_key = deserialize_public_key(self.database.get_public_key(username).encode(self.FORMAT))
        if not verify(json.dumps(msg_json).encode(self.FORMAT), signature.encode(self.FORMAT), public_key):
            message = {'status': False, 'message': 'NOT VERIFIED', 'nonce': nonce}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return

        group_id = msg_json['group_id']
        if not self.database.has_group(group_id):
            message = {'status': False, 'message': 'GROUP NOT FOUND!', 'nonce': nonce}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return

        target_username = msg_json['username']
        if not self.database.has_user(target_username):
            message = {'status': False, 'message': 'USER NOT FOUND!', 'nonce': nonce}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return

        if not self.database.is_owner_of_group(username, group_id):
            message = {'status': False, 'message': 'ONLY OWNER CAN DELETE MEMBERS!', 'nonce': nonce}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return

        if not self.database.is_member_of_group(target_username, group_id):
            message = {'status': False, 'message': 'USER IS NOT MEMBER OF THE GROUP!', 'nonce': nonce}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return

        if self.database.is_owner_of_group(target_username, group_id):
            message = {'status': False, 'message': 'USER IS OWNER OF THE GROUP!', 'nonce': nonce}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return

        self.database.delete_member(group_id, target_username)

        message = {'status': True, 'message': 'SUCCESSFULLY DELETED!', 'nonce': nonce}
        signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
        response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
        self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)

    def create_group(self, msg_json, signature, conn, addr, cipher):
        nonce = msg_json['nonce']
        token = msg_json['token']

        if token not in self.users:
            message = {'status': False, 'message': 'NOT VERIFIED TOKEN', 'nonce': nonce}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return
        owner_id = self.users[token][0]

        group_id = msg_json['group_id']
        if self.database.has_group(group_id):
            message = {'status': False, 'message': 'GROUP_ID IS NOT UNIQUE!', 'nonce': nonce}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return

        self.database.insert_group(group_id, owner_id)
        self.database.insert_memeber(group_id, owner_id)

        message = {'status': True, 'message': 'SUCCESSFULLY CREATED!', 'nonce': nonce}
        signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
        response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
        self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)

    def group_message(self, msg_json, signature, conn, addr, cipher):
        nonce = msg_json['nonce']
        group_id = msg_json['group_id']
        token = msg_json['token']

        if token not in self.users:
            message = {'status': False, 'message': 'NOT VERIFIED TOKEN', 'nonce': nonce}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return
        username = self.users[token][0]

        public_key = deserialize_public_key(self.database.get_public_key(username).encode(self.FORMAT))
        if not verify(json.dumps(msg_json).encode(self.FORMAT), signature.encode(self.FORMAT), public_key):
            message = {'status': False, 'message': 'NOT VERIFIED', 'nonce': nonce, 'public_usernames': None}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return

        if not self.database.has_group(group_id):
            message = {'status': False, 'message': 'GROUP NOT FOUND', 'nonce': nonce, 'public_usernames': None}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return

        members = self.database.get_members(group_id)
        public_usernames = []
        for member in members:
            public_username = {'username': member, 'public_key': self.database.get_public_key(member)}
            public_usernames.append(public_username)
        message = {'status': True, 'message': 'OK', 'nonce': nonce, 'public_usernames': public_usernames}
        signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
        response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
        self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)

        params = []
        for member in members:
            if member == username:
                continue
            msg = self.get_msg(conn, addr)
            msg = json.loads(symmetric_decrypt(msg, cipher).decode(self.FORMAT))
            msg_json, signature = msg['message'], msg['signature']

            if not verify(json.dumps(msg_json).encode(self.FORMAT), signature.encode(self.FORMAT), public_key):
                message = {'status': False, 'message': 'NOT VERIFIED', 'nonce': None}
                signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
                response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
                self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
                return

            nonce2 = msg_json['nonce']
            encrypted_text_message = msg_json['encrypted_text_message']
            encrypted_cipher = msg_json['encrypted_cipher']

            params.append((username, member, encrypted_text_message, encrypted_cipher))

            message = {'status': True, 'message': 'OK', 'nonce': nonce2}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
        for param in params:
            self.database.insert_message(param[0], param[1], param[2], param[3])

    def renew_keys(self, msg_json, signature, conn, addr, cipher):
        token = msg_json['token']
        nonce = msg_json['nonce']
        if token not in self.users:
            message = {'status': False, 'message': 'NOT VERIFIED TOKEN', 'nonce': nonce}
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
            return cipher
        message = {'status': True, 'message': 'OK', 'nonce': nonce}
        signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
        response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
        self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)

        try:
            cipher_text = self.get_msg(conn, addr)
            plain = asymmetric_decrypt(cipher_text, self.private_key)
            plain = plain.decode(self.FORMAT)
            plain = json.loads(plain)
            msg = plain['message']
            token, session_key, session_iv, nonce = msg['token'], msg['session_key'].encode(self.FORMAT), \
                                                    msg['session_iv'].encode(self.FORMAT), msg['nonce']
            if token not in self.users:
                print("HERE 1")
                print(f"[UNEXPECTED CLOSE CONNECTION] {addr}")
                exit(-1)
            user = self.users[token]
            del self.users[token]
            token = int.from_bytes(os.urandom(16), byteorder="big")
            self.users[token] = user
            new_cipher = get_cipher(session_key, session_iv)
            message = {'status': True, 'message': 'SUCCESSFULLY CHANGED SESSION KEY',
                       'nonce': nonce, 'token': token}

            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), new_cipher), conn, addr)
        except:
            print("HERE 2")
            print(f"[UNEXPECTED ERROR] {addr}")
            return cipher

        msg = self.get_msg(conn, addr)
        msg = json.loads(symmetric_decrypt(msg, new_cipher).decode(self.FORMAT))
        msg_json, signature = msg['message'], msg['signature']

        token = msg_json['token']
        password = msg_json['password']
        nonce = msg_json['nonce']
        public_key = deserialize_public_key(msg_json['public_key'].encode(self.FORMAT))
        if not verify(json.dumps(msg_json).encode(self.FORMAT), signature.encode(self.FORMAT), public_key):
            print("HERE 3")
            print(f"[UNEXPECTED CLOSE CONNECTION]")
            return cipher
        if token not in self.users:
            print("HERE 4")
            print(f"[UNEXPECTED CLOSE CONNECTION] {addr}")
            return cipher
        username = self.users[token][0]
        save_status, msg = self.update_user(username, password, msg_json['public_key'])
        message = {'status': save_status, 'message': msg, 'nonce': nonce}
        signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
        response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
        self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), new_cipher), conn, addr)

        return new_cipher
