# fake_ssh_server_paramiko_root_fixed.py

import paramiko
import socket
import threading
import datetime
import os

LOG_FILE = "ssh_attempts.log"
HARDCODED_USER = "root"
HARDCODED_PASS = "toor"
HOST_KEY_PATH = "server_host_key"

def log_attempt(username, password="", success=False):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "SUCCESS" if success else "FAIL"
    msg = f"[{ts}] {status} - user: {username}  pass: {password}"
    print(msg)
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(msg + "\n")
    except Exception as e:
        print(f"[LOG ERROR] {e}")

class RootServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        log_attempt(username, password, False)
        if username.lower() == HARDCODED_USER.lower() and password == HARDCODED_PASS:
            log_attempt(username, password, True)
            print(f"[AUTH SUCCESS] {HARDCODED_USER}:{HARDCODED_PASS}")
            self.event.set()
            return paramiko.AUTH_SUCCESSFUL
        print(f"[AUTH FAIL] Rejected {username}:{password}")
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        print(f"[AUTH] Pubkey attempt by {username} - rejected")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        return True

def handle_client(client):
    transport = paramiko.Transport(client)
    
    # Use persistent host key
    if not os.path.exists(HOST_KEY_PATH):
        print("Generating persistent host key...")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(HOST_KEY_PATH)
    host_key = paramiko.RSAKey.from_private_key_file(HOST_KEY_PATH)
    transport.add_server_key(host_key)
    
    server = RootServer()
    transport.start_server(server=server)

    channel = transport.accept(20)
    if channel is None:
        client.close()
        return

    print("[CHANNEL] Session opened")
    channel.send("Last login: Wed Jan 29 23:00:00 2026 from 127.0.0.1\r\n")
    channel.send("root@fakebox:~# ")

    while True:
        try:
            data = channel.recv(1024).decode(errors='ignore').rstrip('\r\n')
            if not data:
                break
            print(f"[CMD] {data}")
            if data.lower() in ('exit', 'quit', 'logout'):
                channel.send("logout\r\nConnection closed.\r\n")
                break
            elif data == "whoami":
                channel.send("root\r\n")
            elif data.strip():
                channel.send(f"{data}: echoed back\r\n")
            channel.send("root@fakebox:~# ")
        except Exception as e:
            print(f"[ERROR] Channel error: {e}")
            break

    channel.close()
    client.close()

def run_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 2222))
    sock.listen(10)
    print("\nParamiko Root SSH Server - port 2222")
    print(f"ONLY root:{HARDCODED_PASS} works")
    print("All attempts logged to ssh_attempts.log\n")

    while True:
        try:
            client, addr = sock.accept()
            print(f"[CONN] New connection from {addr}")
            t = threading.Thread(target=handle_client, args=(client,))
            t.daemon = True
            t.start()
        except KeyboardInterrupt:
            print("\nServer stopped.")
            break
        except Exception as e:
            print(f"[ERROR] {e}")

if __name__ == "__main__":
    run_server()