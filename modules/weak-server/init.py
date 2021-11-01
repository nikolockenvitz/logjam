import subprocess
import re

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

def nginx():
    command = ['nginx']
    return subprocess.check_call(command) == 0

nginx()
addroute("client", "mitm")
traceroute("client")
# Add route to virtual box machine, via MITM
ip_mitm = "172.22.0.11"
ip_firefox_client = "192.168.178.85"
command = "ip route add " + ip_firefox_client + " via " + ip_mitm
subprocess.check_call(command.split())
