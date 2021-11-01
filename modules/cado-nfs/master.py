#!/bin/python
import subprocess
import os
import socket
import pickle
import time
from sys import stdout

PATH = os.getcwd()

def solve_dlp(p, target):
    path = os.getcwd()
    ell = (p - 1) // 2
    cmd = "cado-nfs.py -dlp -ell {} target={} {} --workdir {}/dlp".format(ell,target,p,PATH)
    dlp = subprocess.check_output(cmd.split(), stderr=subprocess.DEVNULL)
    return int(dlp), ell

def eeucl(a,b):
    if (b == 0):
        return a, 1, 0
    d, s, t = eeucl(b, a%b)
    d, s, t = d, t, s - (a//b)*t
    return d, s, t

def crt(a1, n1, a2, n2):
    _, r, s = eeucl(n1, n2)
    x = a1 * s * n2 + a2 * r * n1
    return x


def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('cado', 5000))
        s.listen()
        while(1):
            conn, addr = s.accept()
            with conn:
                print('Connected by', addr)
                time.sleep(1)
                data = None
                data = conn.recv(1024)
                if data:
                    data = pickle.loads(data)
                    print("Received", data)
                    log2, ell = solve_dlp(data['p'], 2)
                    dlp, ell = solve_dlp(data['p'], data['target'])
                    dlp = dlp * pow(log2, -1, ell) % ell

                    # CRT
                    if pow(2, dlp, data['p']) != data['target']:
                        dlp0 = crt(dlp, ell, 0, 2) % (data['p']-1)
                        if pow(2, dlp0, data['p']) == data['target']:
                            dlp = dlp0
                        else:
                            dlp1 = crt(dlp, ell, 1, 2) % (data['p']-1)
                            if pow(2, dlp1, data['p']) == data['target']:
                                dlp = dlp1
                            else:
                                print("ERROR: log(target) is not correct!")
                    conn.send(pickle.dumps(dlp))

if __name__ == "__main__":
    start_server()


