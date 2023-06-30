import json
import shutil
import socket
from datetime import datetime
from enum import Enum
from tabulate import tabulate

from utils.utils import *
from .dataframe import Dataframe


class Menu(Enum):
    MAIN = 1
    ACCOUNT = 2
    DIRECT = 3
    PV = 4
    GROUP = 5
    GROUP_CHAT = 6


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
        self.password = None
        self.token = None
        self.direct_menu_users = {}
        self.pv_username = None
        self.group_menu_groups = {}
        self.group_id = None

        self.server_public_key = load_server_public_key()  # TODO

        self.handshake()

        self.private_key = None
        self.public_key = None

        self.dataframe = Dataframe()

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

    def menu(self, show_menu=True, command=None):
        if self.state == Menu.MAIN:
            if show_menu:
                self.print_main_menu()
            else:
                self.main_menu(command)
        elif self.state == Menu.ACCOUNT:
            if show_menu:
                self.print_account_menu()
            else:
                self.account_menu(command)
        elif self.state == Menu.DIRECT:
            if show_menu:
                self.print_direct_menu()
            else:
                self.direct_menu(command)
        elif self.state == Menu.PV:
            if show_menu:
                self.print_pv_menu()
            else:
                self.pv_menu(command)
        elif self.state == Menu.GROUP:
            if show_menu:
                self.print_group_menu()
            else:
                self.group_menu(command)
        elif self.state == Menu.GROUP_CHAT:
            if show_menu:
                self.print_group_chat_menu()
            else:
                self.group_chat_menu(command)
        if self.state != Menu.MAIN:
            self.update()

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
        table.append(["1"] + ["Direct Chat"])
        table.append(["2"] + ["Create Group"])
        table.append(["3"] + ["Add Member"])
        table.append(["4"] + ["Group Message"])
        table.append(["5"] + ["Online Users"])
        table.append(["6"] + ["Remove Member"])
        table.append(["7"] + ["Update"])
        table.append(["8"] + ["Logout"])
        print()
        print(f'Hello {self.username}!')
        print(tabulate(table, headers=headers))
    
    def print_direct_menu(self):
        table = []
        users = self.dataframe.get_users(self.username, self.password.encode(self.FORMAT))
        headers = ["ID", "Command"]
        table.append(["0"] + ["Back"])
        table.append(["1"] + ["Message"])
        for i, user in enumerate(users):
            table.append([str(i+2)] + [user])
            self.direct_menu_users[str(i+2)] = user
        print()
        print(tabulate(table, headers=headers))

    def print_group_menu(self):
        table = []
        groups = self.dataframe.get_groups(self.username, self.password.encode(self.FORMAT))
        headers = ["ID", "Command"]
        table.append(["0"] + ["Back"])
        table.append(["1"] + ["Message"])
        for i, group in enumerate(groups):
            table.append([str(i+2)] + [group])
            self.group_menu_groups[str(i+2)] = group
        print()
        print(tabulate(table, headers=headers))

    def print_pv_menu(self):
        print(f'#### Private Chat with {self.pv_username} ####\n')
        msgs = self.dataframe.get_messages(self.username, self.password.encode(self.FORMAT),
                                           addressee_username=self.pv_username)
        print(tabulate(msgs, headers=["Time", "User", "Message"]))
        print('\n###################################')
        table = []
        headers = ["ID", "Command"]
        table.append(["0"] + ["Back"])
        table.append(["1"] + ["Message"])
        print(tabulate(table, headers=headers))

    def print_group_chat_menu(self):
        print(f'#### Group Chat with {self.group_id} ####\n')
        msgs = self.dataframe.get_messages(self.username, self.password.encode(self.FORMAT), group_id=self.group_id)
        print(tabulate(msgs, headers=["Time", "User", "Message"]))
        print('\n###################################')
        table = []
        headers = ["ID", "Command"]
        table.append(["0"] + ["Back"])
        table.append(["1"] + ["Message"])
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
        self.send_encrypt_msg(message, with_signature=False)

    def run(self):
        connected = True
        while connected:
            self.menu(show_menu=True)
            command = input()
            if command == 'exit':
                if not self.token:
                    connected = False
                    self.exit()
                else:
                    print("Please logout first")
                continue
            self.menu(show_menu=False, command=command)
        print("Aborting...")

    def main_menu(self, command):
        if command == '1':
            self.register_menu()
        elif command == '2':
            self.login_menu()
        else:
            print("Invalid command")
    
    def account_menu(self, command):
        if command == '1':
            self.state = Menu.DIRECT
        elif command == '2':
            self.create_group()
        elif command == '3':
            self.add_member()
        elif command == '4':
            self.state = Menu.GROUP
        elif command == '5':
            self.show_online_users()
        elif command == '6':
            self.remove_member()
        elif command == '7':
            self.update()
        elif command == '8':
            self.logout()
        else:
            print("Invalid command")
    
    def direct_menu(self, command):
        if command == '0':
            self.direct_menu_users = {}
            self.state = Menu.ACCOUNT
            return
        elif command == '1':
            receiver_username = input('Who do you want to message?\n')
            text_message = input('Enter your message:\n')
            _, server_msg = self.direct(receiver_username, text_message)
            print(server_msg)
            return
        for i, menu_username in self.direct_menu_users.items():
            if command == i:
                self.state = Menu.PV
                self.pv_username = menu_username
                return
        print("Invalid command")

    def group_menu(self, command):
        if command == '0':
            self.group_menu_groups = {}
            self.state = Menu.ACCOUNT
            return
        elif command == '1':
            group_id = input('Which group do you want to message?\n')
            text_message = input('Enter your message:\n')
            _, server_msg = self.group_chat(group_id, text_message)
            print(server_msg)
            return
        for i, menu_group_id in self.group_menu_groups.items():
            if command == i:
                self.state = Menu.GROUP_CHAT
                self.group_id = menu_group_id
                return
        print("Invalid command")
    
    def pv_menu(self, command):
        if command == '0':
            self.pv_username = None
            self.state = Menu.DIRECT
            return
        elif command == '1':
            text_message = input('Enter your message:\n')
            _, server_msg = self.direct(self.pv_username, text_message)
            print(server_msg)
            return
        print("Invalid command")

    def group_chat_menu(self, command):
        if command == '0':
            self.group_id = None
            self.state = Menu.GROUP
            return
        elif command == '1':
            text_message = input('Enter your message:\n')
            _, server_msg = self.group_chat(self.group_id, text_message)
            print(server_msg)
            return
        print("Invalid command")

    def send_encrypt_msg(self, message, with_signature=True):
        if with_signature:
            signature = sign(json.dumps(message).encode(self.FORMAT), self.private_key)
            msg = symmetric_encrypt(json.dumps({'message': message, 'signature': signature.decode(self.FORMAT)}).encode(self.FORMAT), self.session_cipher)
            self.send_msg(msg)
        else:
            msg = symmetric_encrypt(json.dumps({'message': message, 'signature': ''}).encode(self.FORMAT), self.session_cipher)
            self.send_msg(msg)

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
        
        self.send_encrypt_msg(message)
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
        self.send_encrypt_msg(message)

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
        self.send_encrypt_msg(message)

        response = self.get_msg()
        valid, result, params = self.check_response(response, f_response=f_response2, nonce=nonce1)

        if valid:
            self.username = username
            self.password = password
            self.state = Menu.ACCOUNT
            self.token = params[0]
        return valid, result

    def update(self):
        def f_response(plain, nonce):
            if not plain['nonce'] == nonce:
                return False, '[UNEXPECTED SERVER ERROR]', []
            return plain['status'], plain['message'], [plain['nonce2'], plain['updated_messages']]

        nonce = int.from_bytes(os.urandom(16), byteorder="big")
        message = {'command': 'UPDATE',
                   'token': self.token,
                   'nonce': nonce}
        self.send_encrypt_msg(message)

        response = self.get_msg()
        valid, result, params = self.check_response(response, f_response, nonce)
        if not valid:
            return False, result
        nonce2, updated_messages = params[0], params[1]

        message = {'nonce': nonce2}
        self.send_encrypt_msg(message)

        for updated_message in updated_messages:
            encrypted_text_message, encrypted_cipher = updated_message[0], updated_message[1]
            cipher = self.get_chat_cipher(encrypted_cipher)
            text_message = json.loads(symmetric_decrypt(encrypted_text_message.encode(self.FORMAT), cipher).decode(self.FORMAT))
            self.dataframe.store_message(self.username, text_message, self.password.encode(self.FORMAT))

    def get_chat_cipher(self, encrypted_cipher):
        encrypted_cipher = encrypted_cipher.encode(self.FORMAT)
        cipher = json.loads(asymmetric_decrypt(encrypted_cipher, self.private_key).decode(self.FORMAT))
        key, iv = cipher['key'].encode(self.FORMAT), cipher['iv'].encode(self.FORMAT)
        return get_cipher(key, iv)


    def direct(self, target_username, text_message):
        def f_response1(plain, nonce):
            if not plain['nonce'] == nonce:
                return False, '[UNEXPECTED SERVER ERROR]', []
            return plain['status'], plain['message'], [plain['target_public_key']]
        def f_response2(plain, nonce):
            if not plain['nonce'] == nonce:
                return False, '[UNEXPECTED SERVER ERROR]', []
            return plain['status'], plain['message'], []
        
        nonce1 = int.from_bytes(os.urandom(16), byteorder="big")
        message = {'command': 'DIRECT',
                   'token': self.token,
                   'target_username': target_username,
                   'nonce': nonce1}
        self.send_encrypt_msg(message)

        response = self.get_msg()
        valid, result, params = self.check_response(response, f_response=f_response1, nonce=nonce1)
        if not valid:
            return False, result
        
        target_public_key = params[0]
        target_public_key = deserialize_public_key(target_public_key.encode(self.FORMAT))

        key, iv, cipher = set_key()
        key = key.decode(self.FORMAT)
        iv = iv.decode(self.FORMAT)

        formatted_message = json.dumps({'text': text_message,
                                        'sender': self.username,
                                        'receiver': target_username,
                                        'group_id': None,
                                        'time': datetime.now().strftime("%m/%d/%Y, %H:%M:%S")})
        
        encrypted_text_message = symmetric_encrypt(formatted_message.encode(self.FORMAT), cipher).decode(self.FORMAT)
        encrypted_cipher = asymmetric_encrypt(json.dumps({'key': key, 'iv': iv}).encode(self.FORMAT), target_public_key).decode(self.FORMAT)
        nonce2 = int.from_bytes(os.urandom(16), byteorder="big")
        message = {'nonce': nonce2,
                   'encrypted_text_message': encrypted_text_message,
                   'encrypted_cipher': encrypted_cipher}
        self.send_encrypt_msg(message)

        response = self.get_msg()
        valid, result, params = self.check_response(response, f_response=f_response2, nonce=nonce2)
        if not valid:
            return False, result

        self.dataframe.store_message(self.username, json.loads(formatted_message), self.password.encode(self.FORMAT))
        return valid, result

    def logout(self):
        message = {'command': 'LOGOUT', 'token': self.token}
        self.send_encrypt_msg(message)

        self.username = None
        self.password = None
        self.token = None
        self.state = Menu.MAIN
        self.private_key = None
        self.public_key = None
    
    def show_online_users(self):
        def f_response(plain, nonce):
            if not plain['nonce'] == nonce:
                return False, '[UNEXPECTED SERVER ERROR]', []
            return plain['status'], plain['message'], plain['users']
        nonce = int.from_bytes(os.urandom(16), byteorder="big")
        message = {'command': 'ONLINE_USERS', 'token': self.token, 'nonce':nonce}
        self.send_encrypt_msg(message)
        response = self.get_msg()
        status, msg, users = self.check_response(response, f_response=f_response, nonce=nonce)
        if not status:
            print(msg)
            print('UNKNOWN SERVER ERROR')
            return
        table = []
        headers = ["Online", "Users"]
        for i in range(0, len(users), 2):
            u = users[i+1] if i+1<len(users) else ''
            table.append([users[i]] + [u])
        print(tabulate(table, headers=headers))

    def create_group(self):
        def f_response(plain, nonce):
            if not plain['nonce'] == nonce:
                return False, '[UNEXPECTED SERVER ERROR]', []
            return plain['status'], plain['message'], []
        group_id = input("Enter The Group ID:\n")
        nonce = int.from_bytes(os.urandom(16), byteorder="big")
        message = {'command': 'CREATE_GROUP', 'token': self.token, 'group_id': group_id, 'nonce': nonce}
        self.send_encrypt_msg(message)
        response = self.get_msg()
        status, msg, _ = self.check_response(response, f_response=f_response, nonce=nonce)
        print(msg)

    def add_member(self):
        def f_response(plain, nonce):
            if not plain['nonce'] == nonce:
                return False, '[UNEXPECTED SERVER ERROR]', []
            return plain['status'], plain['message'], []

        group_id = input("Enter The Group ID:\n")
        target_username = input("Enter The Username:\n")
        nonce = int.from_bytes(os.urandom(16), byteorder="big")
        message = {'command': 'ADD_MEMBER', 'token': self.token, 'username': target_username,
                   'group_id': group_id, 'nonce': nonce}
        self.send_encrypt_msg(message)
        response = self.get_msg()
        status, msg, _ = self.check_response(response, f_response=f_response, nonce=nonce)
        print(msg)

    def remove_member(self):
        def f_response(plain, nonce):
            if not plain['nonce'] == nonce:
                return False, '[UNEXPECTED SERVER ERROR]', []
            return plain['status'], plain['message'], []

        group_id = input("Enter The Group ID:\n")
        target_username = input("Enter The Username:\n")
        nonce = int.from_bytes(os.urandom(16), byteorder="big")
        message = {'command': 'DELETE_MEMBER', 'token': self.token, 'username': target_username,
                   'group_id': group_id, 'nonce': nonce}
        self.send_encrypt_msg(message)
        response = self.get_msg()
        status, msg, _ = self.check_response(response, f_response=f_response, nonce=nonce)
        print(msg)

    def group_chat(self, group_id, text_message):
        def f_response1(plain, nonce):
            if not plain['nonce'] == nonce:
                return False, '[UNEXPECTED SERVER ERROR]', []
            return plain['status'], plain['message'], [plain['public_usernames']]

        def f_response2(plain, nonce):
            if not plain['nonce'] == nonce:
                return False, '[UNEXPECTED SERVER ERROR]', []
            return plain['status'], plain['message'], []

        nonce1 = int.from_bytes(os.urandom(16), byteorder="big")
        message = {'command': 'GROUP_MESSAGE',
                   'token': self.token,
                   'group_id': group_id,
                   'nonce': nonce1}
        self.send_encrypt_msg(message)

        response = self.get_msg()
        valid, result, params = self.check_response(response, f_response=f_response1, nonce=nonce1)
        if not valid:
            return False, result

        public_usernames = params[0]
        formatted_messages = []
        for public_username in public_usernames:
            public_key = public_username['public_key']
            target_public_key = deserialize_public_key(public_key.encode(self.FORMAT))
            target_username = public_username['username']

            key, iv, cipher = set_key()
            key = key.decode(self.FORMAT)
            iv = iv.decode(self.FORMAT)

            formatted_message = json.dumps({'text': text_message,
                                            'sender': self.username,
                                            'receiver': target_username,
                                            'group_id': group_id,
                                            'time': datetime.now().strftime("%m/%d/%Y, %H:%M:%S")})
            formatted_messages.append(formatted_message)
            encrypted_text_message = symmetric_encrypt(formatted_message.encode(self.FORMAT), cipher).decode(
                self.FORMAT)
            encrypted_cipher = asymmetric_encrypt(json.dumps({'key': key, 'iv': iv}).encode(self.FORMAT),
                                                  target_public_key).decode(self.FORMAT)
            nonce2 = int.from_bytes(os.urandom(16), byteorder="big")
            message = {'nonce': nonce2,
                       'encrypted_text_message': encrypted_text_message,
                       'encrypted_cipher': encrypted_cipher}
            self.send_encrypt_msg(message)

            response = self.get_msg()
            valid, result, params = self.check_response(response, f_response=f_response2, nonce=nonce2)
            if not valid:
                return False, result

        for formatted_message in formatted_messages:
            self.dataframe.store_message(self.username, json.loads(formatted_message),
                                         self.password.encode(self.FORMAT))
        return valid, result
