import os
import json

from platform import system as platformsystem
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from utilities import *

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

if platformsystem() == "Windows":
    os.system("cls")
else:
    os.system("clear")

# Meta Data
class MetaData:
    __version__ = "0.0.2 Alpha"
    __author__ = "Loks0"

# Json Data
with open("config/config.json", "r", encoding="utf-8") as f:
    config = json.load(f)

username = config.get("Username", )
ChoiceStyle = config.get("ChoiceStyle", "->")

with open("config/thems.json", "r") as f:
    thems = json.load(f)

use_them(thems.get(config.get("them", "Default"), {}).get("windows", ""), thems.get(config.get("them", "Default"), {}).get("linux", ""))
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
                        p2p.connect(config, username, ChoiceStyle)
                    elif choice_p2p == 2:
                        p2p.host(config, username, ChoiceStyle)
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
    03. Change them      
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

                    elif choice_conf == 3:
                        def ____them():
                            for i, (name, data) in enumerate(thems.items()):
                                print(f"{i} > {name}")
                            c1 = input(f"Choice@{username} {ChoiceStyle} ")
                            try:
                                c = int(c1.strip())
                                selected_name = list(thems.keys())[c]
                                theme_data = thems[selected_name]
                                use_them(theme_data.get("windows", ""), theme_data.get("linux", ""))
                                config["them"] = selected_name
                                with open("config/config.json", "w", encoding="utf-8") as f:
                                    json.dump(config, f, indent=4)
                                log(f"Theme changed to {selected_name}", 1)
                            except (ValueError, IndexError):
                                log("Wrong choice!", 3)
                        ____them()
                    else:
                        log("Unknown config option!", 3)
            elif choice_main == 4:
                ReadMe()
            elif choice_main == 0:
                clear()
                log("I miss you already!", 3)
                break
            else:
                pass
    except KeyboardInterrupt:
        log("The user has disabled the program", 3, "y")
        break
    break
