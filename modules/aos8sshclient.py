
try:
    import paramiko
except:
    print("Error importing Paramiko module, please install it with \"pip install paramiko\". Quitting...")
    exit(-1)

import time
import re
import socket

class AOS8SSHClient(paramiko.SSHClient):
    def __init__(self):
        super().__init__()
        self.shell = None

    def aos8connect(self, host, username, password):
        self.load_system_host_keys()
        self.connect(host, username, password)
        
    def aos8invoke_shell(self):
        self.shell = self.invoke_shell()

    def aos8close(self):
        self.shell.close()
        self.shell = None
        self.close()

    def aos8execute(self, command):
        if self.shell is not None:
            self.shell.sendall(command) # Future: Add except handling; otherwise current uncaught exception -> bail is acceptable.
            time.sleep(0.5) # Hold this amount of sleep time to allow target to react

            data = ""
            while True:
                try:
                    buffer = self.shell.recv(65535)
                except socket.timeout:
                    break
                
                data += buffer.decode()
                
                # Check for CLI prompt; means command is completed so we don't have to wait for a timeout.
                if re.search('^\([a-zA-Z0-9\-\_]*\) [\^\*]{0,2}\[[a-zA-Z0-9\-\_]*\] #', data, re.MULTILINE):
                    break
            return data

        else:
            return None