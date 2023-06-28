import json
import os
import shutil
import socket
from enum import Enum
import hashlib
from tabulate import tabulate
from utils.utils import *


class Menu(Enum):
    MAIN = 1
    ACCOUNT = 2


class Client:
    def __init__(self):
        self.MAX_LENGTH = 65536
        self.PORT = 5050
        self.FORMAT = 'latin-1'
        self.DISCONNECT_MESSAGE = "!DISCONNECT"
        self.SERVER = socket.gethostbyname(socket.gethostname())
        self.ADDR = (self.SERVER, self.PORT)
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect(self.ADDR)

        self.session_key, self.session_iv, self.session_cipher = set_key()
        
        self.state = Menu.MAIN
        self.username = None
        self.token = None

        self.server_public_key = load_server_public_key()  # TODO

        self.handshake()

        self.private_key = None
        self.public_key = None


    def handshake(self):
        nonce = int.from_bytes(os.urandom(16), byteorder="big")
        plain_json = {'message': {'session_key': self.session_key.decode(self.FORMAT), 'session_iv': self.session_iv.decode(self.FORMAT), 'nonce':nonce}, 
                      'signature': ''}
        
        plain = json.dumps(plain_json).encode(self.FORMAT)

        encrypted_message = asymmetric_encrypt(plain, self.server_public_key)
        self.send_msg(encrypted_message)

        response = self.get_msg()
        response = json.loads(symmetric_decrypt(response, self.session_cipher).decode(self.FORMAT))

        if response['nonce'] == nonce:
            return
        else:
            print("[UNEXPECTED SERVER ERROR]")
            exit(-1)


    def menu(self, print=True, command=None):
        if self.state == Menu.MAIN:
            if print:
                self.print_main_menu()
            else:
                self.main_menu(command)
        elif self.state == Menu.ACCOUNT:
            if print:
                self.print_account_menu()
            else:
                self.account_menu(command)

    def print_main_menu(self):
        table = []
        headers = ["ID", "Command"]
        table.append(["1"] + ["Register"])
        table.append(["2"] + ["Login"])
        print()
        print(tabulate(table, headers=headers))

    def print_account_menu(self):
        table = []
        headers = ["ID", "Command"]
        table.append(["1"] + ["Establish"])
        table.append(["2"] + ["Direct Chat"])
        table.append(["3"] + ["Create Group"])
        table.append(["4"] + ["Add Member"])
        table.append(["5"] + ["Group Message"])
        table.append(["6"] + ["Online Users"])
        table.append(["7"] + ["Remove Member"])
        table.append(["8"] + ["Logout"])
        print()
        print(f'Hello {self.username}!')
        print(tabulate(table, headers=headers))

    def send_msg(self, msg):
        self.client.send(msg)

    def get_msg(self):
        try:
            msg = self.client.recv(self.MAX_LENGTH)
            return msg
        except:
            print("[UNEXPECTED SERVER ERROR]")
            exit(-1)

    def start(self):
        self.run()

    def exit(self):
        message = {'command': self.DISCONNECT_MESSAGE}
        msg = symmetric_encrypt(json.dumps({'message': message, 'signature': ''}).encode(self.FORMAT), self.session_cipher)
        self.send_msg(msg)


    def run(self):
        connected = True
        while connected:
            self.menu(print=True)
            command = input()
            if command == 'exit':
                if not self.token:
                    connected = False
                    self.exit()
                else:
                    print("Please logout first")
                continue
            self.menu(print=False, command=command)
        print("Aborting...")

    def main_menu(self, command):
        if command == '1':
            self.register_menu()
        elif command == '2':
            self.login_menu()
        else:
            print("Invalid command")

    def register(self, username, password):
        def f_response(plain, nonce):
            if not plain['nonce'] == nonce:
                return False, '[UNEXPECTED SERVER ERROR]'
            return plain['status'], plain['message'], []
        
        self.private_key, self.public_key = set_keys()
        nonce = int.from_bytes(os.urandom(16), byteorder="big")
        message = {'command': 'REGISTER',
                    'username': username,
                    'password': password,
                    'nonce': nonce,
                    'public_key': serialize_public_key(self.public_key).decode(self.FORMAT)}
        
        signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
        msg = symmetric_encrypt(json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)}).encode(self.FORMAT), self.session_cipher)
        self.send_msg(msg)
        response = self.get_msg()

        status, msg, _ = self.check_response(response, f_response, nonce)
        return status, msg

    def check_response(self, response, f_response, nonce=None):
        response = json.loads(symmetric_decrypt(response, self.session_cipher).decode(self.FORMAT))
        signature = response['signature']
        plain = response['message']
        if verify(json.dumps(plain).encode(self.FORMAT), signature.encode(self.FORMAT), self.server_public_key):
            return f_response(plain, nonce)
        else:
            return False, '[UNEXPECTED SERVER ERROR]', []

    def save_info(self, username, password):
        if not os.path.isdir('./keys'):
            os.mkdir('./keys')

        if not os.path.isdir(f'./keys/{username}'):
            os.mkdir(f'./keys/{username}')
        else:
            shutil.rmtree(f'./keys/{username}')
            os.mkdir(f'./keys/{username}')

        save_key(self.private_key, username, password)
        self.private_key = None
        self.public_key = None

    def register_menu(self):
        username = input('Enter username:\n')
        password = input('Enter password:\n')
        status, server_msg = self.register(username, password)
        print(server_msg)
        if status:
            self.save_info(username, password)

    def login_menu(self):
        username = input('Enter username:\n')
        password = input('Enter password:\n')
        key_path = os.path.join('keys', username, 'key.pem')
        if not os.path.isfile(key_path):
            print(f'NO KEY FOR {username}')
            return   
        try:
            private_key, public_key = get_keys(key_path, password)
        except Exception:
            print(f"WRONG PASSWORD")
            return
        self.private_key = private_key
        self.public_key = public_key
        status, server_msg = self.login(username, password)
        print(server_msg)
    
    def login(self, username, password):
        def f_response1(plain, nonce):
            return plain['status'], plain['message'], [plain['salt'], plain['nonce']]
        def f_response2(plain, nonce):
            if not plain['nonce'] == nonce:
                return False, '[UNEXPECTED SERVER ERROR]', []
            return plain['status'], plain['message'], [plain['token']]
        
        nonce1 = int.from_bytes(os.urandom(16), byteorder="big")
        message = {'command': 'LOGIN',
                   'username': username,
                   'nonce': nonce1}
        signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
        msg = symmetric_encrypt(json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)}).encode(self.FORMAT), self.session_cipher)
        self.send_msg(msg)

        response = self.get_msg()
        valid, result, params = self.check_response(response, f_response=f_response1)
        if not valid:
            return False, result
        salt, nonce2 = params[0], params[1]

        salt = str(salt)
        salty_password = f'{password}_{salt}'
        h_salty_password = hashlib.sha256(salty_password.encode(self.FORMAT)).hexdigest()
        h_password = f'{h_salty_password}_{nonce2}'
        hh_password = hashlib.sha256(h_password.encode(self.FORMAT)).hexdigest()
        message = {'hh_password': hh_password}
        signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
        msg = symmetric_encrypt(json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)}).encode(self.FORMAT), self.session_cipher)
        self.send_msg(msg)

        response = self.get_msg()
        valid, result, params = self.check_response(response, f_response=f_response2, nonce=nonce1)

        if valid:
            self.username = username
            self.state = Menu.ACCOUNT
            self.token = params[0]
        return valid, result
    
    def establish(self, target_username):
        def f_response1(plain, nonce):
            if not plain['nonce'] == nonce:
                return False, '[UNEXPECTED SERVER ERROR]', []
            return plain['status'], plain['message'], [plain['target_public_key']]
        def f_response2(plain, nonce):
            if not plain['nonce'] == nonce:
                return False, '[UNEXPECTED SERVER ERROR]', []
            return plain['status'], plain['message'], []
        
        nonce1 = int.from_bytes(os.urandom(16), byteorder="big")
        message = {'command': 'ESTABLISH',
                   'token': self.token,
                   'target_username': target_username,
                   'nonce': nonce1}
        signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
        msg = symmetric_encrypt(json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)}).encode(self.FORMAT), self.session_cipher)
        self.send_msg(msg)

        response = self.get_msg()
        valid, result, params = self.check_response(response, f_response=f_response1, nonce=nonce1)
        if not valid:
            return False, result
        
        target_public_key = params[0]
        target_public_key = deserialize_public_key(target_public_key.encode(self.FORMAT))

        key, iv, _ = set_key()
        key = asymmetric_encrypt(key, target_public_key).decode(self.FORMAT)
        iv = asymmetric_encrypt(iv, target_public_key).decode(self.FORMAT)
        print(key, iv)

        nonce2 = int.from_bytes(os.urandom(16), byteorder="big")
        message = {'nonce': nonce2,
                   'preshared_key': key,
                   'preshared_iv': iv}
        signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
        msg = symmetric_encrypt(json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)}).encode(self.FORMAT), self.session_cipher)
        self.send_msg(msg)

        response = self.get_msg()
        valid, result, params = self.check_response(response, f_response=f_response2, nonce=nonce2)
        if not valid:
            return False, result

        return valid, result

    
    def establish_menu(self):
        target_username = input('Enter target username:\n')
        _, server_msg = self.establish(target_username)
        print(server_msg)

    def account_menu(self, command):
        if command == '1':
            self.establish_menu()
        elif command == '2':
            pass
        elif command == '6':
            self.show_online_users()
        elif command == '8':
            self.logout()
        else:
            print("Invalid command")

    def logout(self):
        message = {'command': 'LOGOUT', 'token': self.token}
        signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
        msg = symmetric_encrypt(json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)}).encode(self.FORMAT), self.session_cipher)
        self.send_msg(msg)

        self.username = None
        self.token = None
        self.state = Menu.MAIN
        self.private_key = None
        self.public_key = None
    
    def show_online_users(self):
        def f_response(plain, nonce):
            return plain['status'], plain['message'], plain['users']
        nonce = int.from_bytes(os.urandom(16), byteorder="big")
        message = {'command': 'ONLINE_USERS', 'token': self.token, 'nonce':nonce}
        signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
        msg = symmetric_encrypt(json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)}).encode(self.FORMAT), self.session_cipher)
        self.send_msg(msg)
        response = self.get_msg()
        status, msg, users = self.check_response(response, f_response=f_response)
        if not status:
            print('UNKNOWN SERVER ERROR')
            return
        table = []
        headers = ["Online", "Users"]
        for i in range(0, len(users), 2):
            u = users[i+1] if i+1<len(users) else ''
            table.append([users[i]] + [u])
        print(tabulate(table, headers=headers))
        