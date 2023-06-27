import hashlib
import json
import os
import socket
import threading

from parse import parse
from .database import Database
from utils.utils import asymmetric_encrypt, set_keys, sign, asymmetric_decrypt, verify, save_server_keys, \
    load_server_keys, deserialize_public_key


class Server:
    def __init__(self):
        self.MAX_LENGTH = 2048
        self.PORT = 5050
        self.SERVER = socket.gethostbyname(socket.gethostname())
        self.ADDR = (self.SERVER, self.PORT)
        self.FORMAT = 'utf-8'
        self.DISCONNECT_MESSAGE = "!DISCONNECT"

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(self.ADDR)

        if not os.path.isfile('server-keys.pem'):
            self.private_key, self.public_key = set_keys()
            save_server_keys(self.private_key, self.public_key)
        else:
            self.private_key, self.public_key = load_server_keys()
        print('server public key: ', self.public_key)
        self.database = Database()

        self.users = {}  # username -> (conn, addr) TODO: change maybe

    def get_msg(self, conn, addr):
        try:
            cipher = conn.recv(self.MAX_LENGTH).decode(self.FORMAT)
            cipher = json.loads(cipher)
            msg = asymmetric_decrypt(cipher['message'], self.private_key)
            return msg, cipher['signature']
        except:
            print(f"[UNEXPECTED CLOSE CONNECTION] {addr}")
            exit(-1)

    def send_msg(self, msg, conn, addr):
        conn.send(msg.encode(self.FORMAT))

    def send_json(self, dic, conn, addr):
        data = json.dumps(dic)
        conn.send(bytes(data, encoding=self.FORMAT))
        print(f"JSON sent to {addr}")

    def get_json(self, conn, addr):
        try:
            js = conn.recv(self.MAX_LENGTH).decode(self.FORMAT)
            dic = json.loads(js)
            return dic
        except:
            print(f"[UNEXPECTED ERROR WHILE GETTING JSON FROM] {addr}")
            exit(-1)

    def handle_client(self, conn, addr):
        print(f"[NEW CONNECTION] {addr} connected.")
        connected = True
        while connected:
            msg, signature = self.get_msg(conn, addr)

            try:
                msg_json = json.loads(msg)
            except TypeError:
                print(f"[UNEXPECTED CLOSE CONNECTION] {addr}")
                exit(-1)

            msg_command = msg_json['command']
            if msg_command == 'REGISTER':
                response = self.register(msg_json)

            if msg_command == self.DISCONNECT_MESSAGE:
                connected = False
                continue
            elif msg.startswith('REGISTER'):
                self.register(msg, conn, addr)
            elif msg.startswith('LOGIN'):
                self.login(msg, conn, addr)
            else:
                print('Invalid msg - ignored')
            self.send_msg(response, conn, addr)
        print(f"[CLOSE CONNECTION] {addr} closed.")

    def start(self):
        self.server.listen()
        print(f"[LISTENING] Server is listening on {self.SERVER}")
        while True:
            conn, addr = self.server.accept()
            thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            thread.start()
            print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")

    def register(self, msg_json, signature):
        username = msg_json['username']
        password = msg_json['password']
        nonce = msg_json['nonce']
        public_key = deserialize_public_key(msg_json['public_key'])

        if not verify(json.dump(msg_json), signature, public_key):
            print(f"[UNEXPECTED CLOSE CONNECTION]")
            exit(-1)

        save_status, msg = self.save_user(username, password, public_key)
        message, encrypted_message = asymmetric_encrypt({'message': msg, 'nonce': nonce,
                                                         'status': save_status},
                                                        key=public_key)
        signature = sign(message, self.private_key)
        response = json.dumps({'message': encrypted_message, 'signature': signature})

        return response

    def save_user(self, username, password, public_key):
        if self.database.has_user(username):
            return False, 'USERNAME ALREADY EXISTS'
        salt = int.from_bytes(os.urandom(16), byteorder="big")
        salty_password = f'{password}_{salt}'
        h_password = hashlib.sha256(salty_password).hexdigest()
        self.database.insert_user(username=username, h_password=h_password, public_key=public_key, salt=salt)
        return True, 'REGISTER SUCCESSFUL'

    def login(self, msg, conn, addr):
        parsed = parse("LOGIN {} {}", msg)
        username = parsed[0]
        password = parsed[1]  # TODO: hash password
        if self.database.has_user(username):
            if self.database.check_password(username, password):
                self.users[username] = (conn, addr)
                self.send_msg('SUCCESSFUL', conn, addr)
            else:
                self.send_msg('WRONG PASSWORD', conn, addr)
        else:
            self.send_msg('USERNAME NOT EXISTS', conn, addr)
