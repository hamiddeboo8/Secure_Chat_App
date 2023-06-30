import json
import os
from utils.utils import encrypt_user_messages, decrypt_user_messages

class Dataframe:
    def __init__(self, df_path='data/messages'):
        self.df_path = df_path
        if not os.path.isdir('data'):
            os.mkdir('data')
        if not os.path.isdir(df_path):
            os.mkdir(df_path)

    def store_message(self, username, data, password=None):
        
        if not os.path.isdir(os.path.join(self.df_path, username)):
            os.mkdir(f'{self.df_path}/{username}')

        if not os.path.isfile(os.path.join(self.df_path, username, 'data.ci')):
            list_messages = []
        else:
            fp = open(os.path.join(self.df_path, username, 'data.ci'), 'rb')
            msgs = decrypt_user_messages(fp.read(), password=password)
            list_messages = json.loads(msgs)
            fp.close()

        list_messages.append(data)
        js_msgs = json.dumps(list_messages)

        fp = open(os.path.join(self.df_path, username, 'data.ci'), 'wb')
        fp.write(encrypt_user_messages(js_msgs, password=password))
        fp.close()
    
    def get_users(self, username, password):
        if not os.path.isfile(os.path.join(self.df_path, username, 'data.ci')):
            return []
        fp = open(os.path.join(self.df_path, username, 'data.ci'), 'rb')
        msgs = decrypt_user_messages(fp.read(), password=password)
        list_messages = json.loads(msgs)
        fp.close()
        list_messages = list(filter(lambda elem: elem['group_id'] is None, list_messages))
        users = set()
        for msg in list_messages:
            users.add(msg['sender'])
            users.add(msg['receiver'])
        return list(users)

    def get_groups(self, username, password):
        if not os.path.isfile(os.path.join(self.df_path, username, 'data.ci')):
            return []
        fp = open(os.path.join(self.df_path, username, 'data.ci'), 'rb')
        msgs = decrypt_user_messages(fp.read(), password=password)
        list_messages = json.loads(msgs)
        fp.close()
        list_messages = list(filter(lambda elem: elem['group_id'] is not None, list_messages))
        groups = set()
        for msg in list_messages:
            groups.add(msg['group_id'])
        return list(groups)
    
    def get_messages(self, username, password, addressee_username=None, group_id=None):
        # returns list of (time, username, msg) sorted by time
        if not os.path.isfile(os.path.join(self.df_path, username, 'data.ci')):
            return []
        fp = open(os.path.join(self.df_path, username, 'data.ci'), 'rb')
        msgs = decrypt_user_messages(fp.read(), password=password)
        list_messages = json.loads(msgs)
        fp.close()
        list_messages = list(filter(lambda elem: elem['group_id'] == group_id, list_messages))
        self_chat = username == addressee_username
        msgs = []
        for msg in list_messages:
            if group_id is not None:
                msgs.append((msg['time'], msg['sender'], msg['text']))
            elif self_chat and msg['sender'] == username and msg['receiver'] == username:
                msgs.append((msg['time'], msg['sender'], msg['text']))
            elif not self_chat:
                if msg['sender'] == addressee_username or msg['receiver'] == addressee_username:
                    msgs.append((msg['time'], msg['sender'], msg['text']))
        return sorted(msgs, key=lambda x: x[0])
