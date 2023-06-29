import json
import os

class Dataframe:
    def __init__(self, df_path='data/messages'):
        self.df_path = df_path
        if not os.path.isdir(df_path):
            os.mkdir(df_path)


    def store_message(self, username, data, password=None):
        
        if not os.path.isdir(f'{self.df_path}/{username}'):
            os.mkdir(f'{self.df_path}/{username}')

        if not os.path.isfile(f'{self.df_path}/{username}/data.json'):
            list_messages = []
        else:
            with open(f'{self.df_path}/{username}/data.json') as fp:
                list_messages = json.load(fp)

        list_messages.append(data)

        with open(f'{self.df_path}/{username}/data.json', 'w') as fp:
            json.dump(list_messages, fp)
    
    