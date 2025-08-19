import socket
import base64

SERVER_IP = "192.168.1.54"
SERVER_PORT = 9988

def receive_file(conn, save_path):
    # najpierw 8 bajtów długości
    size_data = conn.recv(8)
    if not size_data:
        return False

    size = int.from_bytes(size_data, "big")
    if size == 0:
        return False

    data = b""
    while len(data) < size:
        packet = conn.recv(size - len(data))
        if not packet:
            break
        data += packet

    decoded = base64.b64decode(data)

    with open(save_path, "wb") as f:
        f.write(decoded)

    return True

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((SERVER_IP, SERVER_PORT))
        print("[+] Połączono z serwerem")

        # odbiór client.py
        if receive_file(client, "client/client.py"):
            print("[+] Zaktualizowano client.py")
        else:
            print("[!] Nie udało się pobrać client.py")

        # odbiór config.json
        if receive_file(client, "client/config.json"):
            print("[+] Zaktualizowano config.json")
        else:
            print("[!] Nie udało się pobrać config.json")

if __name__ == "__main__":
    main()
