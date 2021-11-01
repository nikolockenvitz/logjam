#!/bin/python
import socket
import pickle
import time
from configparser import RawConfigParser
import paramiko
import threading

SSH_CONFIG_FILENAME = ".ssh_config"

ssh = None
ssh_connected = False
is_disabled = False

def ssh_exec(command):
    if (is_disabled):
        raise Exception("cado-ssh is disabled via config")
    while(not ssh_connected or not ssh):
        time.sleep(.5)
    stdin, stdout, stderr = ssh.exec_command(command)
    return stdout.read().decode()

def connect_ssh():
    global ssh, ssh_connected, is_disabled
    config = RawConfigParser()
    config.read(SSH_CONFIG_FILENAME)
    try:
        ssh_config = config["ssh"]
        username = ssh_config["username"]
        password = ssh_config["password"]
        host = ssh_config["host"]
        is_disabled = ("disabled" in ssh_config and ssh_config["disabled"] == "True")
    except Exception as err:
        print("ERROR: SSH connection not configured! You need to specify username, password, and host in", SSH_CONFIG_FILENAME)
        raise err

    if (is_disabled):
        print("cado-ssh is disabled via config and will not connect")
        return

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=username, password=password)
    ssh_connected = True

    print("SSH: Connected to", host, "as", ssh_exec("whoami"))

threading.Thread(target=connect_ssh).start()



def solve_dlp(p, target):
    ell = (p - 1) // 2
    # TODO
    cmd = "echo 42" # "cado-nfs.py -dlp -ell {} target={} {} --workdir {}/dlp".format(ell,target,p,PATH)
    dlp = ssh_exec(cmd)
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
        s.bind(('cado-ssh', 5000))
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
                    log2, ell = solve_dlp(data['p'], 2) # TODO: only compute once? Actually this is also in output of cado-nfs computation for each target
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
