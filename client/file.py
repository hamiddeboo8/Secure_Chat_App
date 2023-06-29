import os.path


def make_message(src, dst, message, mode):
    if not os.path.isdir(f'messages'):
        os.mkdir(f'messages')
    if not os.path.isdir(f'messages/{src}'):
        os.mkdir(f'messages/{src}')
    if not os.path.isdir(f'messages/{src}/{dst}'):
        os.mkdir(f'messages/{src}/{dst}')

    with open(f'messages/{src}/{dst}/{mode}.txt', 'a') as f:
        f.write(message)
        f.write('\n.....................................\n')