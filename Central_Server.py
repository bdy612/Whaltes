import socket
import threading
import json
import os
import time

class CentralServer:
    def __init__(self, host='0.0.0.0', port=9999):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(100)
        
        self.clients = {} # {username: client_socket}
        self.data_file = "server_data.json"
        self.load_data()
        
        print(f"Central Chat Server started on {self.host}:{self.port}")
        
    def load_data(self):
        if os.path.exists(self.data_file):
            with open(self.data_file, 'r') as f:
                self.data = json.load(f)
        else:
            self.data = {"users": {}} # {username: {friends: [], offline_msgs: []}}
            
    def save_data(self):
        with open(self.data_file, 'w') as f:
            json.dump(self.data, f, indent=4)

    def start(self):
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"New connection from {addr}")
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        username = None
        try:
            while True:
                message = client_socket.recv(4096).decode('utf-8')
                if not message:
                    break
                
                try:
                    data = json.loads(message)
                    msg_type = data.get("type")
                    
                    if msg_type == "login":
                        username = data.get("username")
                        if username:
                            self.clients[username] = client_socket
                            self.register_user(username)
                            print(f"User logged in: {username}")
                            self.send_json(client_socket, {"type": "system", "message": f"Welcome {username}!"})
                            self.check_offline_messages(username)
                            
                    elif msg_type == "add_friend":
                        target = data.get("target")
                        if username and target:
                            self.handle_friend_request(username, target)
                            
                    elif msg_type == "chat":
                        target = data.get("target")
                        text = data.get("message")
                        if username and target and text:
                            self.route_message(username, target, text)
                            
                except json.JSONDecodeError:
                    pass
                    
        except Exception as e:
            print(f"Error with client {username}: {e}")
        finally:
            if username and username in self.clients:
                del self.clients[username]
            client_socket.close()

    def register_user(self, username):
        if username not in self.data["users"]:
            self.data["users"][username] = {"friends": [], "offline_msgs": []}
            self.save_data()

    def handle_friend_request(self, sender, target):
        if target not in self.data["users"]:
            self.send_to_user(sender, {"type": "system", "message": f"User '{target}' does not exist."})
            return
            
        # For simplicity, auto-add for now (or we can implement request logic)
        # Adding to both sides
        if target not in self.data["users"][sender]["friends"]:
            self.data["users"][sender]["friends"].append(target)
        if sender not in self.data["users"][target]["friends"]:
            self.data["users"][target]["friends"].append(sender)
        self.save_data()
        
        self.send_to_user(sender, {"type": "system", "message": f"You are now friends with {target}"})
        self.send_to_user(target, {"type": "system", "message": f"{sender} added you as a friend."})

    def route_message(self, sender, target, text):
        msg_data = {
            "type": "chat",
            "sender": sender,
            "message": text,
            "timestamp": time.time()
        }
        
        if target in self.clients:
            # User is online
            self.send_json(self.clients[target], msg_data)
        elif target in self.data["users"]:
            # User is offline, save message
            self.data["users"][target]["offline_msgs"].append(msg_data)
            self.save_data()
            self.send_to_user(sender, {"type": "system", "message": f"User offline. Message saved for {target}."})
        else:
            self.send_to_user(sender, {"type": "system", "message": f"User {target} not found."})

    def check_offline_messages(self, username):
        msgs = self.data["users"][username]["offline_msgs"]
        if msgs:
            for msg in msgs:
                self.send_to_user(username, msg)
            self.data["users"][username]["offline_msgs"] = []
            self.save_data()

    def send_to_user(self, username, data):
        if username in self.clients:
            self.send_json(self.clients[username], data)

    def send_json(self, socket, data):
        try:
            socket.send(json.dumps(data).encode('utf-8'))
        except:
            pass

if __name__ == "__main__":
    server = CentralServer()
    server.start()
