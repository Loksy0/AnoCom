import os
import json

import socket
import base64
import threading

from platform import system as platformsystem

if platformsystem() == "Windows":
    os.system("cls")
else:
    os.system("clear")

# Meta Data
class MetaData:
    __version__ = "0.0.1 Alpha"
    __author__ = "Loks0"

# Json Data
with open("config.json", "r", encoding="utf-8") as f:
    config = json.load(f)

username = config.get("Username", )
ChoiceStyle = config.get("ChoiceStyle", "->")

# Utilities
def log(message, type, next_line=False):
    if next_line is False or next_line == "n":
        prefixes = {1: "[+]", 2: "[-]", 3: "[!]"}
    elif next_line is True or next_line == "y":
        prefixes = {1: "\n[+]", 2: "\n[-]", 3: "\n[!]"}
    print(f"{prefixes.get(type, '[?]')} {message}")

def clear():
    if platformsystem() == "Windows":
        os.system("cls")
    else:
        os.system("clear")

# ReadMe
def ReadMe():
    clear()
    info2print = f"""AnoCom Version -> {MetaData.__version__}
AnoCom Author -> {MetaData.__author__}

# P2P chat encryption structure.
  1. Handshake 
    - ECDH (X25519) 
    - Ed25519 signatures for authentication.
  2. Message encryption
    - Double Ratchet 
  3. Transport
    - Custom UDP protocol
    - KEach message is encoded using b64url before sending to facilitate communication between users.
"""
    print(info2print)
    input("Click enter to back...")
    clear()
# P2P
def p2p_host():
    clear()
    port_input = input("Enter port (default 25336): ").strip()
    key_input = input("Enter access key (optional): ").strip()

    port = int(port_input) if port_input else 25336
    access_key = key_input if key_input else None

    log(f"Hosting on port {port}", 1)
    if access_key:
        log("Access key required for connection", 1)
    else:
        log("No access key required", 1)

    def handle_client(conn, addr):
        log(f"Connection from {addr}", 1)

        if access_key:
            request = {"Message": "Pls enter the key"}
            encoded_request = base64.b64encode(json.dumps(request).encode()).decode()
            conn.send(encoded_request.encode())

            attempts = 0
            while attempts < 4:
                try:
                    data = conn.recv(4096)
                    decoded = base64.b64decode(data).decode()
                    response = json.loads(decoded)
                    received_key = response.get("Message", "")

                    if received_key != access_key:
                        attempts += 1
                        if attempts >= 4:
                            log("Too many failed attempts. Disconnecting.", 2)
                            conn.close()
                            return
                        else:
                            retry = {"Message": "Wrong key"}
                            encoded_retry = base64.b64encode(json.dumps(retry).encode()).decode()
                            conn.send(encoded_retry.encode())
                    else:
                        log("Correct key received. Connection accepted.", 1)
                        success = {"Message": "Success"}
                        encoded_success = base64.b64encode(json.dumps(success).encode()).decode()
                        conn.send(encoded_success.encode())
                        conn.close()
                        return
                except Exception as e:
                    log(f"Error during key exchange: {e}", 3)
                    conn.close()
                    return

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", port))
    server.listen(5)

    log("Waiting for connections...", 1)
    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()
    except KeyboardInterrupt:
        log("Host stopped by user", 3)
        server.close()

def p2p_connect():
    clear()
    ip = input("Enter IP to connect to: ").strip()
    port_input = input("Enter port (default 25336): ").strip()
    port = int(port_input) if port_input else 25336

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((ip, port))
        log("Connected to host", 1)

        data = client.recv(4096)
        decoded = base64.b64decode(data).decode()
        message = json.loads(decoded)

        if message.get("Message") == "Pls enter the key":
            attempts = 0
            while attempts < 4:
                key = input("Enter access key: ").strip()
                response = {"Message": key}
                encoded_response = base64.b64encode(json.dumps(response).encode()).decode()
                client.send(encoded_response.encode())

                data = client.recv(4096)
                decoded = base64.b64decode(data).decode()
                message = json.loads(decoded)

                if message.get("Message") == "Success":
                    log("Connection accepted!", 1)
                    client.close()
                    return
                elif message.get("Message") == "Wrong key":
                    attempts += 1
                    log(f"Wrong key! Attempts left: {4 - attempts}", 2)
                else:
                    log("Unexpected response from host", 3)
                    break

            log("Too many failed attempts. Disconnecting.", 3)
            client.close()
            return

        elif message.get("Message") == "Success":
            log("Connected without key", 1)
            client.close()
            return
        else:
            log("Unexpected response from host", 3)
            client.close()
            return

    except Exception as e:
        log(f"Connection error: {e}", 3)

while True:
    try:
        while True:
            print(f"""Welcom back {username}! |-| AnoCom {MetaData.__version__}
    1. Servers
    2. P2P
    3. Config
    4. ReadMe
    0. Exit""")
            inp_main = input(f"Choice@{username} {ChoiceStyle} ")
            choice_main = None

            try:
                choice_main = int(inp_main.strip())

            except:
                log("Wrong choice!", 3)

            if choice_main == 1:
                pass
            elif choice_main == 2:
                clear()
                while True:
                    print(f"""AnoCom {MetaData.__version__}
    1. Connect
    2. Host
    0. Back""")
                    inp_p2p = input(f"Choice@{username} {ChoiceStyle} ")
                    choice_p2p = None

                    try:
                        choice_p2p = int(inp_p2p.strip())
                    except:
                        log("Wrong choice!", 3)
                    
                    if choice_p2p == 1:
                        p2p_connect()
                    elif choice_p2p == 2:
                        p2p_host()
                    elif choice_p2p == 0:
                        clear()
                        break
                    else:
                        pass

            elif choice_main == 3:
                clear()
                while True:
                    print(f"""Config
    00. Back  
                          
    01. Change username
    02. Change input style         
""")
                    inp_conf = input(f"Choice@{username} {ChoiceStyle} ")
                    try:
                        choice_conf = int(inp_conf.strip())
                    except:
                        log("Wrong config choice!", 3)
                        continue

                    if choice_conf == 0:
                        clear()
                        break

                    elif choice_conf == 1:
                        new_username = input("Enter new username: ").strip()
                        if new_username:
                            username = new_username
                            config["Username"] = username
                            with open("config.json", "w", encoding="utf-8") as f:
                                json.dump(config, f, indent=4)
                            log(f"Username changed to {username}", 1)
                        else:
                            log("Username cannot be empty!", 3)

                    elif choice_conf == 2:
                        new_style = input("Enter new input style (e.g. ->, >>, ::): ").strip()
                        if new_style:
                            ChoiceStyle = new_style
                            config["ChoiceStyle"] = ChoiceStyle
                            with open("config.json", "w", encoding="utf-8") as f:
                                json.dump(config, f, indent=4)
                            log(f"Input style changed to {ChoiceStyle}", 1)
                        else:
                            log("Input style cannot be empty!", 3)

                    else:
                        log("Unknown config option!", 3)
            elif choice_main == 4:
                ReadMe()
            elif choice_main == 0:
                clear()
                log("I miss you already!", 3)
            else:
                pass
    except KeyboardInterrupt:
        log("The user has disabled the program", 3, "y")
        break
    break
