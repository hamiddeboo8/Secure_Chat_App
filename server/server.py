import hashlib
import json
import os
import socket
import threading

from parse import parse
from .database import Database
from utils.utils import asymmetric_encrypt, set_keys, sign, asymmetric_decrypt, verify, save_server_keys, \
    load_server_keys, deserialize_public_key, get_cipher, symmetric_decrypt, symmetric_encrypt


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
        print('server public key: ', self.public_key)
        self.database = Database()

        self.users = {}  # username -> (conn, addr) TODO: change maybe

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
            session_key, session_iv, nonce = msg['session_key'].encode(self.FORMAT), msg['session_iv'].encode(self.FORMAT), msg['nonce']
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
            try:
                msg_json, signature = msg['message'], msg['signature']
            except TypeError:
                print(f"[UNEXPECTED CLOSE CONNECTION] {addr}")
                exit(-1)

            msg_command = msg_json['command']
            if msg_command == 'REGISTER':
                response = self.register(msg_json, signature)

            if msg_command == self.DISCONNECT_MESSAGE:
                connected = False
                continue
            else:
                print('Invalid msg - ignored')
            self.send_msg(symmetric_encrypt(response.encode(self.FORMAT), cipher), conn, addr)
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
        public_key = deserialize_public_key(msg_json['public_key'].encode(self.FORMAT))
        if not verify(json.dumps(msg_json).encode(self.FORMAT), signature.encode(self.FORMAT), public_key):
            print(f"[UNEXPECTED CLOSE CONNECTION]")
            exit(-1)

        save_status, msg = self.save_user(username, password, msg_json['public_key'])
        message = {'status': save_status, 'message': msg, 'nonce': nonce}
        signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
        response = json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)})
        return response

    def save_user(self, username, password, public_key):
        if self.database.has_user(username):
            return False, 'USERNAME ALREADY EXISTS'
        salt = int.from_bytes(os.urandom(8), byteorder="big")
        salty_password = f'{password}_{salt}'
        h_password = hashlib.sha256(salty_password.encode(self.FORMAT)).hexdigest()
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
