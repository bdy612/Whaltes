import socket
import threading
import time
import logging

class Server:
    def __init__(self, host, port):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen(5)  # Allow up to 5 connections
        self.running = True
        self.clients = []  # List to store connected clients
        self.message_handler = None
        self.client_kicked_handler = None  # Callback for when a client is kicked
        self.log = []
        
        # Start the listener in a separate thread
        self.listener_thread = threading.Thread(target=self.listen_for_clients)
        self.listener_thread.daemon = True
        self.listener_thread.start()
    
    def listen_for_clients(self):
        """Listen for incoming client connections"""
        self.server_socket.settimeout(1.0)  # Add timeout to allow checking running flag
        
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                self.log.append(f"Connection from {client_address}")
                
                # Add client to the list
                self.clients.append((client_socket, client_address))
                
                # Start a thread to handle this client
                client_thread = threading.Thread(target=self.handle_client, 
                                               args=(client_socket, client_address))
                client_thread.daemon = True
                client_thread.start()
                
            except socket.timeout:
                # This allows the server to check if it should continue running
                continue
            except Exception as e:
                if self.running:  # Only log if still supposed to be running
                    self.log.append(f"Error accepting connection: {e}")
    
    def handle_client(self, client_socket, client_address):
        """Handle communication with a connected client"""
        try:
            while self.running:
                # Set a timeout so we can check if server is still running
                client_socket.settimeout(1.0)
                
                try:
                    # Receive data from the client
                    data = client_socket.recv(1024).decode()
                    
                    if data:
                        self.log.append(f"Received from {client_address}: {data}")
                        
                        # If a message handler is set, call it
                        if self.message_handler:
                            self.message_handler(client_address, data)
                        
                        # Send an acknowledgment back to the client
                        response = f"Server received: {data}"
                        client_socket.send(response.encode())
                    else:
                        # Empty data means client disconnected
                        self.log.append(f"Client {client_address} disconnected")
                        break
                        
                except socket.timeout:
                    # Just a timeout, continue the loop
                    continue
                except Exception as e:
                    self.log.append(f"Error communicating with {client_address}: {e}")
                    break
        
        finally:
            # Remove client from list and close socket
            self.remove_client(client_socket, client_address)
    
    def kick_client(self, client_address):
        """Forcibly disconnect a client"""
        for client_socket, addr in self.clients:
            if addr == client_address:
                try:
                    # Send a kick message to the client
                    try:
                        client_socket.send("KICKED_BY_SERVER".encode())
                    except:
                        pass  # Client might already be unresponsive
                    
                    # Close the socket
                    client_socket.close()
                    
                    # Remove from our list
                    self.clients.remove((client_socket, addr))
                    
                    # Call the kicked handler if set
                    if self.client_kicked_handler:
                        self.client_kicked_handler(addr, "Kicked by server")
                    
                    self.log.append(f"Client {addr} has been kicked")
                    return True
                except Exception as e:
                    self.log.append(f"Error kicking client {addr}: {e}")
                    return False
        
        self.log.append(f"Client {client_address} not found")
        return False
    
    def remove_client(self, client_socket, client_address):
        """Remove a client from the list and close their socket"""
        if (client_socket, client_address) in self.clients:
            self.clients.remove((client_socket, client_address))
            
            try:
                client_socket.close()
            except:
                pass  # Socket might already be closed
    
    def broadcast(self, message):
        """Send a message to all connected clients"""
        disconnected_clients = []
        
        for client_socket, client_address in self.clients:
            try:
                client_socket.send(message.encode())
                self.log.append(f"Broadcast message sent to {client_address}")
            except Exception:
                # Mark this client for removal
                disconnected_clients.append((client_socket, client_address))
        
        # Remove disconnected clients
        for client in disconnected_clients:
            if client in self.clients:
                self.clients.remove(client)
    
    def send_to_client(self, client_address, message):
        """Send a message to a specific client by address"""
        for client_socket, addr in self.clients:
            if addr == client_address:
                try:
                    client_socket.send(message.encode())
                    self.log.append(f"Message sent to {client_address}")
                    return True
                except Exception as e:
                    self.log.append(f"Error sending to {client_address}: {e}")
                    return False
        
        self.log.append(f"Client {client_address} not found")
        return False
    
    def set_message_handler(self, handler_function):
        """Set a function to handle incoming messages"""
        self.message_handler = handler_function
    
    def set_client_kicked_handler(self, handler_function):
        """Set a function to handle client kick events"""
        self.client_kicked_handler = handler_function
    
    def close(self):
        """Close the server and all client connections"""
        self.running = False
        
        # Close all client connections
        for client_socket, _ in self.clients:
            try:
                client_socket.close()
            except:
                pass
        self.clients = []
        
        # Close server socket
        try:
            self.server_socket.close()
        except:
            pass