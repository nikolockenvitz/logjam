from flask import Flask
from flask_cors import CORS
import threading

app = Flask(__name__)
CORS(app)

import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

commands = [
    "console.log('Hello, World!')",
    # now that the client does the computation, we can even implement fibonacci inefficiently :)
    "function fib(n) { if (n<2) {return 1;} else { return fib(n-1) +fib(n-2);}}",
    "for (var i=0; i<10; i++) { console.log(fib(i));}",
    "document.querySelector('p').textContent += ' ... So Long, and Thanks for All the CPU';",
]

@app.route("/")
def flask_test():
    # TODO: multiple clients could be distinguished by a self-generated id
    global commands
    try:
        cmd = commands.pop(0)
        return cmd
    except:
        return ""

def command_input():
    global commands
    while(1):
        cmd = input(">>> ")
        commands.append(cmd)

threading.Thread(target=command_input).start()
