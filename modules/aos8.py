
try:
    import paramiko
except:
    print("Error importing Paramiko module, please install it with \"pip install paramiko\". Quitting...")
    exit(-1)

import time
import re
import socket


# Check if string contains AOS 8 prompt -> Implies target is ready to accept next command, or end of output.
def is_contain_prompt(input_str = ""):
    input_str = input_str.replace('\r', '')

    if re.search('^\([a-zA-Z0-9\-\_]*\) [\^\*]{0,2}\[[a-zA-Z0-9\-\_]*\] [\^\*]{0,2}\(?[a-zA-Z0-9\-\_]*\)?\s?#', input_str, re.MULTILINE):
        return True
    elif re.search('^\([a-zA-Z0-9\-\_]*\) [\^\*]{0,2}\s?#', input_str, re.MULTILINE):
        return True
    else:
        return False

# Remove the executed command and CLI prompt from output
def clean_output(output, command = ""):
    output = output.replace('\r', '')
    lines = output.splitlines(True)
    clean_output = []

    for l in lines:
        if is_contain_prompt(l):
            pass
        elif command != "" and re.search(command, l, re.MULTILINE):
            pass
        else:
            clean_output.append(l.rstrip())

    return "\n".join(clean_output)


class AOS8SSHClient(paramiko.SSHClient):
    def __init__(self):
        super().__init__()
        self.shell = None

    def aos8connect(self, host, username, password, secure_login=True):
        self.load_system_host_keys()

        if secure_login == False:
            self.set_missing_host_key_policy(paramiko.client.AutoAddPolicy)
        
        self.connect(host, username = username, password = password)

    def aos8invoke_shell(self):
        self.shell = self.invoke_shell()
        self.aos8execute("no paging")

    def aos8close(self):
        self.shell.close()
        self.shell = None
        self.close()

    def aos8execute(self, command):
        if self.shell is not None:
            self.shell.sendall(command + "\n") # Future: Add except handling; otherwise current uncaught exception -> bail is acceptable.
            time.sleep(0.5) # Hold this amount of sleep time to allow target to react

            data = ""
            buffer = ""

            while True:
                try:
                    buffer = self.shell.recv(65535)
                except socket.timeout:
                    break
                
                data += buffer.decode()
                
                # Check for CLI prompt; means command is completed so we don't have to wait for a timeout.
                if is_contain_prompt(data):
                    break

            # Cleanup before returning data.
            return clean_output(data, command)

        else:
            return None