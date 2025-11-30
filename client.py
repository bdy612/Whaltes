import socket
import threading
import json
import logging

# Create a logger
logger = logging.getLogger(__name__)

class Client:
    def __init__(self, server_host, server_port):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((server_host, server_port))
        self.running = True
        self.message_callback = None
        self.disconnect_callback = None
        logger.info(f"Connected to server at {server_host}:{server_port}")
        
        # Start listening thread
        self.listen_thread = threading.Thread(target=self.listen_for_messages)
        self.listen_thread.daemon = True
        self.listen_thread.start()
    
    def listen_for_messages(self):
        """Listen for incoming messages from the server"""
        self.client_socket.settimeout(1.0)  # Set timeout to allow checking running flag
        
        while self.running:
            try:
                # Wait for messages from the server
                message = self.client_socket.recv(1024).decode()
                
                if message:
                    logger.info(f"Message from server: {message}")
                    
                    # Check if we've been kicked
                    if message == "KICKED_BY_SERVER":
                        logger.info("You have been kicked from the server")
                        if self.disconnect_callback:
                            self.disconnect_callback("Kicked by server")
                        self.running = False
                        break
                    
                    # If a callback is registered, call it with the message
                    if self.message_callback:
                        self.message_callback(message)
                else:
                    # Empty response means server disconnected
                    logger.info("Disconnected from server")
                    if self.disconnect_callback:
                        self.disconnect_callback("Server disconnected")
                    self.running = False
                    break
                    
            except socket.timeout:
                # Just a timeout, continue the loop
                continue
            except Exception as e:
                if self.running:  # Only show error if still supposed to be running
                    logger.error(f"Error receiving from server: {e}")
                if self.disconnect_callback:
                    self.disconnect_callback(f"Connection error: {e}")
                self.running = False
                break
    
    def send(self, message):
        """Send a message to the server"""
        try:
            self.client_socket.send(message.encode())
            return True
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            return False
    
    def send_encrypted_message(self, message, encryption_data):
        """Send a message with encryption data"""
        try:
            # Create a packet containing both the message and encryption info
            packet = {
                "encrypted_message": message,
                "encryption_data": encryption_data
            }
            
            # Convert to JSON string and send
            json_data = json.dumps(packet)
            self.client_socket.send(json_data.encode())
            return True
        except Exception as e:
            logger.error(f"Error sending encrypted message: {e}")
            return False
    
    def set_message_callback(self, callback_function):
        """Set a function to call when messages are received"""
        self.message_callback = callback_function
    
    def set_disconnect_callback(self, callback_function):
        """Set a function to call when disconnected"""
        self.disconnect_callback = callback_function
    
    def close(self):
        """Close the connection to the server"""
        self.running = False
        self.client_socket.close()