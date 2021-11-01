import socket
import pickle

HOST = "cado"
PORT = 5000

def compute (p, target):
    result = ""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        data = {'p': p, 'target': target}
        s.send(pickle.dumps(data))
        result = s.recv(1024)
        result = pickle.loads(result)
        print('Received', result)
    return result
