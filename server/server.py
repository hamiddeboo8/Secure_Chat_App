import json
import socket
import threading
from parse import parse
from .database import Database


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

        self.database = Database()

        self.users = {}  # username -> (conn, addr) TODO: change maybe

    def get_msg(self, conn, addr):
        try:
            msg = conn.recv(self.MAX_LENGTH).decode(self.FORMAT)
            return msg
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
            msg = self.get_msg(conn, addr)
            print(f"[{addr}] {msg}")
            if msg == self.DISCONNECT_MESSAGE:
                connected = False
                continue
            elif msg.startswith('REGISTER'):
                self.register(msg, conn, addr)
            elif msg.startswith('LOGIN'):
                self.login(msg, conn, addr)
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
    
    def register(self, msg, conn, addr):
        parsed = parse("REGISTER {} {}", msg)
        username = parsed[0]
        password = parsed[1] # TODO: hash password
        if self.database.has_user(username):
            self.send_msg('USERNAME ALREADY EXISTS', conn, addr)
            return
        self.database.insert_user(username, password)
        self.send_msg('REGISTER SUCCESSFUL', conn, addr)
    
    def login(self, msg, conn, addr):
        parsed = parse("LOGIN {} {}", msg)
        username = parsed[0]
        password = parsed[1] # TODO: hash password
        if self.database.has_user(username):
            if self.database.check_password(username, password):
                self.users[username] = (conn, addr)
                self.send_msg('SUCCESSFUL', conn, addr)
            else:
                self.send_msg('WRONG PASSWORD', conn, addr)
        else:
            self.send_msg('USERNAME NOT EXISTS', conn, addr)
        

