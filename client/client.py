import json
import os
import shutil
import socket
from enum import Enum

from tabulate import tabulate

from utils.utils import asymmetric_encrypt, set_keys, set_key, sign, asymmetric_decrypt, verify, save_key, \
    load_server_public_key, serialize_public_key, symmetric_decrypt, symmetric_encrypt


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
        # Exception?
        self.state = Menu.MAIN
        self.username = None

        self.server_public_key = load_server_public_key()  # TODO

        self.handshake()

        self.private_key = None
        self.public_key = None

        self.nonce = None

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
        print(tabulate(table, headers=headers))

    def print_account_menu(self):
        print(f'Hello {self.username}!')
        table = []
        headers = ["ID", "Command"]
        table.append(["1"] + ["Connection"])
        table.append(["2"] + ["Direct Chat"])
        table.append(["3"] + ["Create Group"])
        table.append(["4"] + ["Add Member"])
        table.append(["5"] + ["Group Message"])
        table.append(["6"] + ["Online Users"])
        table.append(["7"] + ["Remove Member"])
        table.append(["8"] + ["Logout"])
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

    def run(self):
        connected = True
        while connected:
            self.menu(print=True)
            command = input()
            if command == 'exit':
                connected = False
                self.send_msg(self.DISCONNECT_MESSAGE)
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
        self.private_key, self.public_key = set_keys()
        self.nonce = int.from_bytes(os.urandom(16), byteorder="big")
        message = {'command': 'REGISTER',
                    'username': username,
                    'password': password,
                    'nonce': self.nonce,
                    'public_key': serialize_public_key(self.public_key).decode(self.FORMAT)}
        
        signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
        return symmetric_encrypt(json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)}).encode(self.FORMAT), self.session_cipher)

    def register_response(self, response):
        response = json.loads(symmetric_decrypt(response, self.session_cipher).decode(self.FORMAT))
        signature = response['signature']
        plain = response['message']
        if verify(json.dumps(plain).encode(self.FORMAT), signature.encode(self.FORMAT), self.server_public_key):
            nonce = plain['nonce']
            if not nonce == self.nonce:
                return '[UNEXPECTED SERVER ERROR]'
            status = plain['status']
            if not status:
                return False, plain['message']
            return True, plain['message']
        else:
            return False, '[UNEXPECTED SERVER ERROR]'

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
        msg = self.register(username, password)
        self.send_msg(msg)
        response = self.get_msg()
        status, server_msg = self.register_response(response)
        print(server_msg)
        if status:
            self.save_info(username, password)

    def login_menu(self):
        username = input('Enter username:\n')
        password = input('Enter password:\n')
        self.send_msg('LOGIN', username, password)
        response = self.get_msg()
        print(response)
        if response == 'SUCCESSFUL':
            self.username = username
            self.state = Menu.ACCOUNT

    def account_menu(self, command):
        if command == '1':
            pass
        elif command == '2':
            pass
        elif command == '8':
            self.logout()
        else:
            print("Invalid command")

    def logout(self):
        self.username = None
        self.state = Menu.MAIN
