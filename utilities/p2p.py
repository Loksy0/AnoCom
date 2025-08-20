import os
import json
import time
import socket
import curses
import base64
import threading

from platform import system as platformsystem
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

from .message import *

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

CHUNK_SIZE = 4096

def pack_encrypted_json_rsa(author: str, message: str, aes_key: bytes, peer_rsa_pub_b64: str) -> bytes:
    aes_encrypted_b64 = aes_encrypt_text(aes_key, message)
    rsa_encrypted_b64 = rsa_encrypt_bytes(peer_rsa_pub_b64, aes_encrypted_b64.encode("utf-8"))

    payload = {
        "Author": author,
        "Message": rsa_encrypted_b64
    }
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def unpack_encrypted_json_rsa(data: bytes, aes_key: bytes, rsa_priv_b64: str) -> dict:
    payload = json.loads(data.decode("utf-8"))
    aes_encrypted_b64 = rsa_decrypt_bytes(rsa_priv_b64, payload["Message"]).decode("utf-8")
    decrypted_msg = aes_decrypt_text(aes_key, aes_encrypted_b64)

    return {
        "Author": payload["Author"],
        "Message": decrypted_msg
    }


def chat_ui(stdscr, conn_or_client, aes_key, rsa_priv_b64, peer_rsa_pub_b64, config, username, ChoiceStyle):
    curses.curs_set(1)
    stdscr.nodelay(True)
    stdscr.clear()
    height, width = stdscr.getmaxyx()
    input_win = curses.newwin(1, width, height - 1, 0)
    chat_win = curses.newwin(height - 1, width, 0, 0)

    messages = []
    scroll_offset = 0
    lock = threading.Lock()
    disconnected = threading.Event()

    def receive():
        nonlocal scroll_offset
        buffer = b""
        while not disconnected.is_set():
            try:
                data = conn_or_client.recv(4096)
                if not data:
                    break
                buffer += data

                try:
                    msg = unpack_encrypted_json_rsa(buffer, aes_key, rsa_priv_b64)
                    buffer = b""  # zresetuj po poprawnym dekodowaniu
                except Exception:
                    continue  # jeszcze nie pełna paczka

                author = msg["Author"]
                content = msg["Message"]

                if content.startswith("/file_start:"):
                    _, filename, size = content.split(":", 2)
                    expected_size = int(size)
                    file_data = b""

                    while len(file_data) < expected_size:
                        chunk = conn_or_client.recv(CHUNK_SIZE)
                        if not chunk:
                            break
                        file_data += chunk

                    output_path = f"downloads/received_{filename}"
                    with open(output_path, "wb") as f:
                        f.write(file_data)

                    with lock:
                        messages.append(f"[+] Odebrano plik: {filename}")
                        scroll_offset = 0

                elif content == "/exit":
                    with lock:
                        messages.append(f"[!] {author} disconnected.")
                        scroll_offset = 0
                    disconnected.set()
                    break

                else:
                    with lock:
                        messages.append(f"{author} -> {content}")
                        scroll_offset = 0
            except Exception as e:
                with lock:
                    messages.append(f"[!] Receive error: {e}")
                break

    def render():
        while not disconnected.is_set():
            with lock:
                chat_win.erase()
                visible_msgs = messages[max(0, len(messages) - (height - 2) - scroll_offset):len(messages) - scroll_offset]
                for i, msg in enumerate(visible_msgs):
                    chat_win.addstr(i, 0, msg[:width - 1])
                chat_win.refresh()
            time.sleep(0.1)

    def send_file(filepath):
        filename = os.path.basename(filepath)
        size = os.path.getsize(filepath)

        # Wyślij nagłówek
        header = f"/file_start:{filename}:{size}"
        packed = pack_encrypted_json_rsa(username, header, aes_key, peer_rsa_pub_b64)
        conn_or_client.sendall(packed)

        # Wyślij plik w chunkach
        with open(filepath, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                conn_or_client.sendall(chunk)

        # Stopka
        footer = f"/file_end:{filename}"
        packed = pack_encrypted_json_rsa(username, footer, aes_key, peer_rsa_pub_b64)
        conn_or_client.sendall(packed)

        with lock:
            messages.append(f"[+] Wysłano plik: {filename}")

    def input_loop():
        nonlocal scroll_offset
        while not disconnected.is_set():
            input_win.erase()
            input_win.addstr(0, 0, f"{username}@message {ChoiceStyle} ")
            input_win.refresh()
            curses.echo()
            try:
                text = input_win.getstr().decode().strip()
                curses.noecho()

                if text == "/exit":
                    packed = pack_encrypted_json_rsa(username, "/exit", aes_key, peer_rsa_pub_b64)
                    conn_or_client.send(packed)
                    with lock:
                        messages.append("[!] You disconnected.")
                        scroll_offset = 0
                    disconnected.set()
                    break

                if text.startswith("/send "):
                    filepath = text[6:].strip()
                    if os.path.isfile(filepath):
                        send_file(filepath)
                    else:
                        with lock:
                            messages.append(f"[!] Plik nie istnieje: {filepath}")
                            scroll_offset = 0
                    continue

                packed = pack_encrypted_json_rsa(username, text, aes_key, peer_rsa_pub_b64)
                conn_or_client.send(packed)
                with lock:
                    messages.append(f"{username} -> {text}")
                    scroll_offset = 0
            except Exception as e:
                with lock:
                    messages.append(f"[!] Input error: {e}")
                break

    threading.Thread(target=receive, daemon=True).start()
    threading.Thread(target=render, daemon=True).start()
    input_loop()

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

def host(config, username, ChoiceStyle):
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

    connection_established = threading.Event()

    def handle_client(conn, addr):
        if connection_established.is_set():
            log(f"Rejected connection from {addr} — already connected", 2)
            conn.close()
            return

        connection_established.set()
        log(f"Connection from {addr}", 1)

        try:
            # Step 1: Access key check
            if access_key:
                conn.send(base64.b64encode(json.dumps({"Message": "Pls enter the key"}).encode()))
                for _ in range(4):
                    data = conn.recv(4096)
                    if not data:
                        break
                    decoded = base64.b64decode(data).decode()
                    response = json.loads(decoded)
                    if response.get("Message") != access_key:
                        conn.send(base64.b64encode(json.dumps({"Message": "Wrong key"}).encode()))
                    else:
                        conn.send(base64.b64encode(json.dumps({"Message": "Success"}).encode()))
                        break
                else:
                    conn.send(base64.b64encode(json.dumps({"Message": "Too many attempts"}).encode()))
                    conn.close()
                    return
            else:
                conn.send(base64.b64encode(json.dumps({"Message": "Success"}).encode()))

            # Step 2: Handshake (ECDH + Ed25519)
            ecdh_priv = x25519.X25519PrivateKey.generate()
            ecdh_pub = ecdh_priv.public_key()

            ed_signing, ed_verify = generate_ed25519_keypair()

            rsa_priv_b64, rsa_pub_b64 = generate_rsa_keypair()

            ecdh_pub_bytes = ecdh_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            handshake_payload = {
                "ECDH_Public": base64.b64encode(ecdh_pub_bytes).decode(),
                "Ed25519_Public": base64.b64encode(bytes(ed_verify)).decode(),
                "Signature": base64.b64encode(sign_message(ed_signing, ecdh_pub_bytes)).decode(),
                "RSA_Public": rsa_pub_b64  
            }
            conn.send(base64.b64encode(json.dumps(handshake_payload).encode()))

            data = conn.recv(4096)
            peer_handshake = json.loads(base64.b64decode(data).decode())

            peer_ecdh_pub = base64.b64decode(peer_handshake["ECDH_Public"])
            peer_ed_pub = base64.b64decode(peer_handshake["Ed25519_Public"])
            peer_signature = base64.b64decode(peer_handshake["Signature"])
            peer_rsa_pub_b64 = peer_handshake.get("RSA_Public") 

            if not verify_signature(peer_ed_pub, peer_ecdh_pub, peer_signature):
                log("Signature verification failed", 3)
                conn.close()
                return

            # Step 3: Derive shared AES key 
            key_len = config.get("AES_Key_Length", 32)
            hkdf_info = config.get("HKDF_Info", "AnoCom handshake").encode()

            peer_pub_obj = x25519.X25519PublicKey.from_public_bytes(peer_ecdh_pub)
            shared_secret = ecdh_priv.exchange(peer_pub_obj)

            aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=key_len,
                salt=None,
                info=hkdf_info
            ).derive(shared_secret)

            log("Handshake complete, AES key derived.", 1)

            # Step 4: Dummy Ratchet
            class DummyRatchet:
                def encrypt(self, msg): return msg
                def decrypt(self, msg): return msg
            ratchet = DummyRatchet()

            curses.wrapper(lambda stdscr: chat_ui(stdscr, conn, aes_key, rsa_priv_b64, peer_rsa_pub_b64, config, username, ChoiceStyle))

        finally:
            conn.close()
            connection_established.clear()
            log("Connection closed", 2)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", port))
    server.listen(1)

    log("Waiting for one connection...", 1)
    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()
    except KeyboardInterrupt:
        log("Host stopped by user", 3)
        server.close()

def connect(config, username, ChoiceStyle):
    clear()
    ip = input("Enter IP to connect to: ").strip()
    port_input = input("Enter port (default 25336): ").strip()
    port = int(port_input) if port_input else 25336

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((ip, port))
        log("Connected to host", 1)

        data = client.recv(4096)
        if not data:
            log("No response from host", 3)
            client.close()
            return

        decoded = base64.b64decode(data).decode()
        message = json.loads(decoded)

        # --- Access key ---
        if message.get("Message") == "Pls enter the key":
            for attempts in range(4):
                key = input("Enter access key: ").strip()
                response = {"Message": key}
                client.send(base64.b64encode(json.dumps(response).encode()))
                data = client.recv(4096)
                if not data:
                    break
                decoded = base64.b64decode(data).decode()
                message = json.loads(decoded)
                if message.get("Message") == "Success":
                    break
                elif message.get("Message") == "Wrong key":
                    log(f"Wrong key! Attempts left: {3 - attempts}", 2)
                elif message.get("Message") == "Too many attempts":
                    log("Too many failed attempts. Host disconnected.", 3)
                    client.close()
                    return
            else:
                log("Failed to authenticate", 3)
                client.close()
                return
        elif message.get("Message") != "Success":
            log("Unexpected response from host", 3)
            client.close()
            return

        # --- Step 2: Handshake (ECDH + Ed25519 + RSA) ---
        ecdh_priv = x25519.X25519PrivateKey.generate()
        ecdh_pub = ecdh_priv.public_key()

        ed_signing, ed_verify = generate_ed25519_keypair()

        rsa_priv_b64, rsa_pub_b64 = generate_rsa_keypair()

        ecdh_pub_bytes = ecdh_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        handshake_payload = {
            "ECDH_Public": base64.b64encode(ecdh_pub_bytes).decode(),
            "Ed25519_Public": base64.b64encode(bytes(ed_verify)).decode(),
            "Signature": base64.b64encode(sign_message(ed_signing, ecdh_pub_bytes)).decode(),
            "RSA_Public": rsa_pub_b64 
        }
        client.send(base64.b64encode(json.dumps(handshake_payload).encode()))

        data = client.recv(4096)
        peer_handshake = json.loads(base64.b64decode(data).decode())

        peer_ecdh_pub = base64.b64decode(peer_handshake["ECDH_Public"])
        peer_ed_pub = base64.b64decode(peer_handshake["Ed25519_Public"])
        peer_signature = base64.b64decode(peer_handshake["Signature"])
        peer_rsa_pub_b64 = peer_handshake.get("RSA_Public") 

        if not verify_signature(peer_ed_pub, peer_ecdh_pub, peer_signature):
            log("Signature verification failed", 3)
            client.close()
            return

        key_len = config.get("AES_Key_Length", 32)
        hkdf_info = config.get("HKDF_Info", "AnoCom handshake").encode()

        peer_pub_obj = x25519.X25519PublicKey.from_public_bytes(peer_ecdh_pub)
        shared_secret = ecdh_priv.exchange(peer_pub_obj)

        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=key_len,
            salt=None,
            info=hkdf_info
        ).derive(shared_secret)

        log("Handshake complete, AES key derived.", 1)

        class DummyRatchet:
            def encrypt(self, msg): return msg
            def decrypt(self, msg): return msg
        ratchet = DummyRatchet()

        curses.wrapper(lambda stdscr: chat_ui(stdscr, client, aes_key, rsa_priv_b64, peer_rsa_pub_b64, config, username, ChoiceStyle))
        client.close()

    except Exception as e:
        log(f"Connection error: {e}", 3)