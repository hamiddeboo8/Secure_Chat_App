import json
import socket
from tabulate import tabulate
from parse import parse
from enum import Enum

class Menu(Enum):
    MAIN = 1
    ACCOUNT = 2

class Client:
    def __init__(self):
        self.MAX_LENGTH = 2048
        self.PORT = 5050
        self.FORMAT = 'utf-8'
        self.DISCONNECT_MESSAGE = "!DISCONNECT"
        self.SERVER = socket.gethostbyname(socket.gethostname())
        self.ADDR = (self.SERVER, self.PORT)
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect(self.ADDR)
        self.state = Menu.MAIN
        self.username = None
    
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
        self.client.send(msg.encode(self.FORMAT))

    def get_msg(self):
        try:
            msg = self.client.recv(self.MAX_LENGTH).decode(self.FORMAT)
            return msg
        except:
            print("[UNEXPECTED SERVER ERROR]")
            exit(-1)

    def get_json(self):
        try:
            js = self.client.recv(self.MAX_LENGTH).decode(self.FORMAT)
            dic = json.loads(js)
            return dic
        except:
            print("[UNEXPECTED SERVER ERROR]")
            exit(-1)

    def send_json(self, path):
        data = json.load(open(path, 'r'))
        data['user'] = self.username
        self.client.send(bytes(json.dumps(data), encoding=self.FORMAT))

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
    
    def register_menu(self):
        username = input('Enter username:\n')
        password = input('Enter password:\n')
        self.send_msg(f'REGISTER {username} {password}')
        response = self.get_msg()
        print(response)
    

    def login_menu(self):
        username = input('Enter username:\n')
        password = input('Enter password:\n')
        self.send_msg(f'LOGIN {username} {password}')
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

