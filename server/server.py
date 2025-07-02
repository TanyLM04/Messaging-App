import socket
import threading
import json

HOST = '127.0.0.1'
PORT = 5000

clients = {}  # socket: username

"""
Not used anymore, from when there weren't chats
def broadcast(message, sender_conn):
    for client in clients:
        if client != sender_conn:
            try:
                client.send(message.encode())
            except:
                client.close()
                del clients[client]
"""
def handle_client(conn, addr):
    try:
        # announce user connected
        username = conn.recv(1024).decode()
        clients[username] = conn
        print(f"[+] {username} connected from {addr}")

        send_user_list()
        broadcast_system(f"{username} joined the chat.")

        while True:
            header_data = conn.recv(4096)  # receive JSON header or chat message
            if not header_data:
                break
            msg_obj = json.loads(header_data.decode())

            if msg_obj["type"] == "chat":
                receiver = msg_obj["receiver"]
                if receiver in clients:
                    clients[receiver].send(header_data)  # forward header
                else:
                    error_msg = {"type": "system", "message": f"User {receiver} not found."}
                    conn.send(json.dumps(error_msg).encode())

            elif msg_obj["type"] == "file":
                receiver = msg_obj["receiver"]
                filesize = msg_obj["filesize"]

                if receiver in clients:
                    # forward file header first
                    clients[receiver].send(header_data)

                    # then forward the file bytes
                    bytes_received = 0
                    while bytes_received < filesize:
                        chunk = conn.recv(min(4096, filesize - bytes_received))
                        if not chunk:
                            break
                        clients[receiver].send(chunk)
                        bytes_received += len(chunk)
                else:
                    error_msg = {"type": "system", "message": f"User {receiver} not found."}
                    conn.send(json.dumps(error_msg).encode())

    except Exception as e:
        print(f"Error in handle_client: {e}")
    finally: # when user disconnects:
        print(f"[-] {username} disconnected.")
        conn.close()
        if username in clients:
            del clients[username] # delete disconnecting user from user list
        send_user_list()
        broadcast_system(f"{username} left the chat.")


def send_user_list():
    user_list = list(clients.keys())
    msg = {
        "type": "user_list",
        "users": user_list
    }
    for conn in clients.values():
        try:
            conn.send(json.dumps(msg).encode())
        except:
            pass

def broadcast_system(message): # send a server message to all users
    msg = {
        "type": "system",
        "message": message
    }
    for conn in clients.values():
        try:
            conn.send(json.dumps(msg).encode())
        except:
            pass


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[✓] Server listening on {HOST}:{PORT}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start_server()