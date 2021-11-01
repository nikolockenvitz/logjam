import subprocess
from subprocess import PIPE
import re
import time

def ping(host):
    command = ['ping', '-c', '1', host]
    return subprocess.check_call(command, stdout=subprocess.DEVNULL) == 0

def traceroute(host):
    command = ['traceroute', host]
    return subprocess.check_call(command) == 0

def resolve(host):
    command = ['ping', '-c', '1', host]
    result = subprocess.check_output(command).decode()
    result = re.split(r'\(|\)', result)[1]
    return result

def addroute(target, gateway):
    target_ip = resolve(target)
    gateway_ip = resolve(gateway)
    command = ['ip', 'route', 'add', target_ip, 'via', gateway_ip]
    return subprocess.check_call(command) == 0

def connect(host, port):
    if port == 80:
        command = "curl http://server:80"
        return subprocess.call(command.split()) == 0
    elif port == 443:
        command = 'openssl s_client -quiet -connect server:443'
        resp, log = subprocess.Popen(command.split(), stdout=PIPE, stdin=PIPE, stderr=PIPE).communicate(b'GET /\n')
        print(resp.decode())

def patch_openssl():
    fn1 = '/usr/ssl/openssl.cnf'
    patch = '''
[ default_conf ]

ssl_conf = ssl_sect

[ssl_sect]

system_default = system_default_sect

[system_default_sect]
MinProtocol = TLSv1.2
CipherString = DEFAULT:@SECLEVEL=0
    '''
    with open(fn1, "a") as f:
        f.write(patch)

    command = "openssl version -a"
    subprocess.call(command.split())
    command = "curl --version"
    subprocess.call(command.split())




patch_openssl()
time.sleep(5) 
addroute("server", "mitm")
traceroute("server")
time.sleep(5)
connect("server",80)
connect("server",443)

