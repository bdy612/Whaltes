"""
Whlates - Secure Encryption Suite
Version 2.7 - 2025 Edition
Super Main File - All modules combined
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog, filedialog
import customtkinter as ctk

# Configure CustomTkinter
ctk.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"
import socket
from threading import Thread
import json
import os
import base64
import hashlib
import itertools
import time
import random
import string
import logging
import shutil
import zipfile
import tempfile
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==================== Hashing Module ====================

class Hashing:
    def __init__(self, data):
        self.hash_types = [
            "sha256",
            "sha512",
            "md5",
            "sha1",
            "sha224",
            "sha384"
        ]
        self.data = data

    def get_hash_types(self):
        return self.hash_types

    def hashing_file(self, file_path, type="sha256"):
        with open(file_path, "rb") as f:
            data = f.read()
            return self.hash(data, type)
    
    def hash(self, data, type="sha256"):
        if isinstance(data, str):
            data = data.encode()
            
        if type=="sha256":
            return hashlib.sha256(data).hexdigest()
        elif type=="sha512":
            return hashlib.sha512(data).hexdigest()
        elif type=="md5":
            return hashlib.md5(data).hexdigest()
        elif type=="sha1":
            return hashlib.sha1(data).hexdigest()
        elif type=="sha224":
            return hashlib.sha224(data).hexdigest()
        elif type=="sha384":
            return hashlib.sha384(data).hexdigest()
        else:
            return "Invalid hash type"
    
    def verify(self, hash, data, type="sha256"):
        return self.hash(data, type) == hash

    def benchmark(self, type="sha256", duration=1.0):
        start = time.time()
        count = 0
        data = "benchmark_data"
        while time.time() - start < duration:
            self.hash(f"{data}{count}", type)
            count += 1
        return count / duration

    def estimate_time(self, length, charset_size, hashrate):
        combinations = charset_size ** length
        seconds = combinations / hashrate
        return seconds

    def crack_bruteforce(self, target_hash, type="sha256", max_length=5, charset=None, callback=None):
        
        if charset is None:
            charset = string.ascii_lowercase + string.digits
            
        for length in range(1, max_length + 1):
            for attempt in itertools.product(charset, repeat=length):
                candidate = "".join(attempt)
                if callback and not callback(candidate):
                    return None # Stop if callback returns False
                    
                if self.hash(candidate, type) == target_hash:
                    return candidate
        return None

# ==================== Encryption Module ====================

class Encription:
    # Encryption type constants
    CAESAR_SUBSTITUTION = 1
    VIGENERE = 2
    AES = 3
    
    @staticmethod
    def get_encryption_types():
        """Return a list of available encryption types"""
        return [
            {"name": "Caesar+Substitution Cipher", "value": Encription.CAESAR_SUBSTITUTION},
            {"name": "Vigenère Cipher", "value": Encription.VIGENERE},
            {"name": "AES Encryption", "value": Encription.AES}
        ]
    
    @staticmethod
    def encrypt(text, params, encryption_type=CAESAR_SUBSTITUTION):
        """
        Encrypt the given text using the specified encryption type and parameters
        Returns a dictionary with encrypted text and information needed for decryption
        """
        if encryption_type == Encription.CAESAR_SUBSTITUTION:
            encrypted_text, substitution_key = Encription._encrypt_caesar_substitution(text, params["shift"])
            return {
                "type": encryption_type,
                "text": encrypted_text,
                "params": {
                    "shift": params["shift"],
                    "substitution_key": substitution_key
                }
            }
        
        elif encryption_type == Encription.VIGENERE:
            encrypted_text = Encription._encrypt_vigenere(text, params["key"])
            return {
                "type": encryption_type,
                "text": encrypted_text,
                "params": {
                    "key": params["key"]
                }
            }
        
        elif encryption_type == Encription.AES:
            encrypted_data = Encription._encrypt_aes(text, params["password"])
            return {
                "type": encryption_type,
                "text": encrypted_data["ciphertext"],
                "params": {
                    "password": params["password"],
                    "salt": encrypted_data["salt"],
                    "iv": encrypted_data["iv"]
                }
            }
        
        else:
            raise ValueError("Unknown encryption type")
    
    @staticmethod
    def decrypt(encryption_result):
        """
        Decrypt text using the information in the encryption_result dictionary
        """
        encryption_type = encryption_result["type"]
        encrypted_text = encryption_result["text"]
        params = encryption_result["params"]
        
        if encryption_type == Encription.CAESAR_SUBSTITUTION:
            return Encription._decrypt_caesar_substitution(
                encrypted_text, 
                params["shift"], 
                params["substitution_key"]
            )
        
        elif encryption_type == Encription.VIGENERE:
            return Encription._decrypt_vigenere(encrypted_text, params["key"])
        
        elif encryption_type == Encription.AES:
            return Encription._decrypt_aes(
                encrypted_text,
                params["password"],
                params["salt"],
                params["iv"]
            )
        
        else:
            raise ValueError("Unknown encryption type")
    
    @staticmethod
    def _encrypt_caesar_substitution(text, shift):
        """
        Encrypt text using a Caesar cipher with a random substitution table
        """
        # Generate substitution key (random mapping for each letter)
        alphabet = string.ascii_lowercase
        shuffled = list(alphabet)
        random.shuffle(shuffled)
        substitution_key = ''.join(shuffled)
        
        # Create translation tables
        caesar_table = str.maketrans(
            alphabet,
            alphabet[shift:] + alphabet[:shift]
        )
        substitution_table = str.maketrans(alphabet, substitution_key)
        
        # Apply Caesar cipher then substitution
        caesar_text = text.lower().translate(caesar_table)
        encrypted_text = caesar_text.translate(substitution_table)
        
        return encrypted_text, substitution_key
    
    @staticmethod
    def _decrypt_caesar_substitution(text, shift, substitution_key):
        """
        Decrypt text that was encrypted with Caesar cipher and substitution
        """
        alphabet = string.ascii_lowercase
        
        # Create reverse translation tables
        reverse_substitution = str.maketrans(substitution_key, alphabet)
        reverse_caesar = str.maketrans(
            alphabet[shift:] + alphabet[:shift],
            alphabet
        )
        
        # First reverse the substitution, then the Caesar shift
        substitution_reversed = text.translate(reverse_substitution)
        decrypted_text = substitution_reversed.translate(reverse_caesar)
        
        return decrypted_text
    
    @staticmethod
    def _encrypt_vigenere(text, key):
        """
        Encrypt text using a Vigenère cipher
        """
        key = key.lower()
        encrypted = []
        key_length = len(key)
        
        for i, char in enumerate(text.lower()):
            if char.isalpha():
                # Convert to 0-25 (a=0, b=1, etc)
                char_num = ord(char) - ord('a')
                key_char = key[i % key_length]
                key_num = ord(key_char) - ord('a')
                
                # Vigenere formula: (char_num + key_num) % 26
                encrypted_num = (char_num + key_num) % 26
                encrypted_char = chr(encrypted_num + ord('a'))
                encrypted.append(encrypted_char)
            else:
                # Keep non-alphabetic characters as is
                encrypted.append(char)
        
        return ''.join(encrypted)
    
    @staticmethod
    def _decrypt_vigenere(text, key):
        """
        Decrypt text that was encrypted with a Vigenère cipher
        """
        key = key.lower()
        decrypted = []
        key_length = len(key)
        
        for i, char in enumerate(text.lower()):
            if char.isalpha():
                # Convert to 0-25
                char_num = ord(char) - ord('a')
                key_char = key[i % key_length]
                key_num = ord(key_char) - ord('a')
                
                # Vigenere decryption: (char_num - key_num) % 26
                decrypted_num = (char_num - key_num) % 26
                decrypted_char = chr(decrypted_num + ord('a'))
                decrypted.append(decrypted_char)
            else:
                decrypted.append(char)
        
        return ''.join(decrypted)
    
    @staticmethod
    def _encrypt_aes(text, password):
        """
        Encrypt text using AES-256 with password-based key derivation
        """
        # Generate a random salt
        salt = get_random_bytes(32)
        
        # Generate key from password and salt using SHA-256
        key = hashlib.sha256(password.encode() + salt).digest()
        
        # Create cipher with a random IV (initialization vector)
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Pad the plaintext to a multiple of 16 bytes
        padded_text = pad(text.encode(), AES.block_size)
        
        # Encrypt
        ciphertext = cipher.encrypt(padded_text)
        
        # Encode binary data as base64 strings for storage/transmission
        return {
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "salt": base64.b64encode(salt).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8')
        }
    
    @staticmethod
    def _decrypt_aes(ciphertext_b64, password, salt_b64, iv_b64):
        """
        Decrypt text that was encrypted with AES
        """
        try:
            # Convert base64 strings back to bytes
            ciphertext = base64.b64decode(ciphertext_b64)
            salt = base64.b64decode(salt_b64)
            iv = base64.b64decode(iv_b64)
            
            # Regenerate the key from password and salt
            key = hashlib.sha256(password.encode() + salt).digest()
            
            # Create cipher for decryption
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            # Decrypt and unpad
            padded_text = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_text, AES.block_size)
            
            return plaintext.decode('utf-8')
        except ValueError as e:
            raise ValueError(f"Decryption error: {str(e)}")
        except Exception as e:
            raise Exception(f"Failed to decrypt: {str(e)}")
    
    @staticmethod
    def encode_encryption_data(encryption_result):
        """
        Convert encryption result to a compact string for transmission
        """
        # Convert bytes to base64 strings for JSON serialization
        # Make a deep copy to avoid modifying the original
        result_copy = dict(encryption_result)
        
        if "params" in result_copy:
            params_copy = dict(result_copy["params"])
            
            # Handle binary data
            for key, value in params_copy.items():
                if isinstance(value, bytes):
                    params_copy[key] = base64.b64encode(value).decode('utf-8')
            
            result_copy["params"] = params_copy
        
        # Convert to JSON string
        return json.dumps(result_copy)
    
    @staticmethod
    def decode_encryption_data(json_string):
        """
        Convert a JSON string back to encryption result for decryption
        """
        try:
            data = json.loads(json_string)
            
            # Convert base64 strings back to bytes if needed
            if "params" in data:
                for key, value in data["params"].items():
                    # Check if this might be base64 encoded bytes
                    try:
                        if isinstance(value, str) and key in ["salt", "iv"]:
                            data["params"][key] = value  # Keep as string, will decode in decrypt
                    except:
                        pass  # Not base64, keep as is
            
            return data
        except Exception as e:
            raise ValueError(f"Failed to decode encryption data: {str(e)}")
    
    @staticmethod
    def encrypt_file(file_path, params, encryption_type=AES):
        """
        Encrypt a file and return base64 encoded data for transmission
        """
        import os
        
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Convert binary data to base64 for text-based encryption
        file_b64 = base64.b64encode(file_data).decode('utf-8')
        
        # Encrypt the base64 string
        encrypted_result = Encription.encrypt(file_b64, params, encryption_type)
        
        # Add filename
        encrypted_result['filename'] = os.path.basename(file_path)
        encrypted_result['original_size'] = len(file_data)
        
        return encrypted_result
    
    @staticmethod
    def decrypt_file(encryption_result, output_path):
        """
        Decrypt file data and save to output_path
        """
        # Decrypt to get base64 string
        decrypted_b64 = Encription.decrypt(encryption_result)
        
        # Decode base64 to binary
        file_data = base64.b64decode(decrypted_b64)
        
        # Write to file
        with open(output_path, 'wb') as f:
            f.write(file_data)
        
        return output_path
    
    @staticmethod
    def encrypt_folder(folder_path, params, encryption_type=AES):
        """
        Encrypt all files in a folder and return as a package
        """
        import os
        import zipfile
        import tempfile
        
        # Create a temporary zip file
        temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
        temp_zip.close()
        
        # Zip the folder
        with zipfile.ZipFile(temp_zip.name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, folder_path)
                    zipf.write(file_path, arcname)
        
        # Encrypt the zip file
        encrypted_result = Encription.encrypt_file(temp_zip.name, params, encryption_type)
        encrypted_result['is_folder'] = True
        encrypted_result['folder_name'] = os.path.basename(folder_path)
        
        # Clean up temp file
        os.unlink(temp_zip.name)
        
        return encrypted_result
    
    @staticmethod
    def decrypt_folder(encryption_result, output_path):
        """
        Decrypt folder package and extract to output_path
        """
        import os
        import zipfile
        import tempfile
        
        # Create temp file for decrypted zip
        temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
        temp_zip.close()
        
        # Decrypt to temp zip file
        Encription.decrypt_file(encryption_result, temp_zip.name)
        
        # Extract zip
        with zipfile.ZipFile(temp_zip.name, 'r') as zipf:
            zipf.extractall(output_path)
        
        # Clean up
        os.unlink(temp_zip.name)
        
        return output_path

# ==================== Server Module ====================

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
        self.listener_thread = Thread(target=self.listen_for_clients)
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
                client_thread = Thread(target=self.handle_client, 
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

# ==================== Client Module ====================

# Create a logger


class Client:
    def __init__(self, server_host, server_port):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((server_host, server_port))
        self.running = True
        self.message_callback = None
        self.disconnect_callback = None
        logger.info(f"Connected to server at {server_host}:{server_port}")
        
        # Start listening thread
        self.listen_thread = Thread(target=self.listen_for_messages)
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

# ==================== GUI Application ====================

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        if hasattr(self.root, 'title'):
            self.root.title("Whlates - Secure Encryption Suite")
        if hasattr(self.root, 'geometry'):
            self.root.geometry("1000x850")
        if hasattr(self.root, 'configure'):
            self.root.configure(bg="#0f172a")
        
        # Configure modern styling
        self.setup_styles()
        
        self.encryption_params = {}
        self.encryption_result = None
        self.server_instance = None
        self.client = None
        self.current_encryption_type = Encription.CAESAR_SUBSTITUTION
        
        # Keep track of connected clients (for server mode)
        self.connected_clients = []
        self.selected_client = None
        
        self.create_ui()
    
    def setup_styles(self):
        """Configure modern dark theme styling"""
        # CustomTkinter handles styling automatically
        pass
    
    def create_ui(self):
        # Create tabview
        self.tabview = ctk.CTkTabview(self.root)
        self.tabview.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.tabview.add("Encryption")
        self.tabview.add("Hashing")
        self.tabview.add("Cracking")
        self.tabview.add("Server")
        self.tabview.add("Client")
        self.tabview.add("Fast Connect")
        
        # Assign frames
        self.encryption_frame = self.tabview.tab("Encryption")
        self.hashing_frame = self.tabview.tab("Hashing")
        self.cracking_frame = self.tabview.tab("Cracking")
        self.server_frame = self.tabview.tab("Server")
        self.client_frame = self.tabview.tab("Client")
        self.fast_connect_frame = self.tabview.tab("Fast Connect")
        
        # Set up each tab
        self.setup_encryption_tab()
        self.setup_hashing_tab()
        self.setup_cracking_tab()
        self.setup_server_tab()
        self.setup_client_tab()
        self.setup_fast_connect_tab()
    
    def setup_encryption_tab(self):
        # Input text area
        ctk.CTkLabel(self.encryption_frame, text="Enter text to encrypt:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.input_text = ctk.CTkTextbox(self.encryption_frame, width=400, height=100)
        self.input_text.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky=(tk.W, tk.E))
        
        # Encryption type selection
        ctk.CTkLabel(self.encryption_frame, text="Encryption Method:").grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        
        # Create combobox for encryption types
        encryption_types = Encription.get_encryption_types()
        encryption_type_names = [t["name"] for t in encryption_types]
        self.encryption_type_combo = ctk.CTkComboBox(self.encryption_frame, values=encryption_type_names, command=self.on_encryption_type_changed_ctk)
        self.encryption_type_combo.set(encryption_type_names[0])  # Set default to first option
        self.encryption_type_combo.grid(row=2, column=1, sticky=tk.W, padx=10, pady=5)
        
        # Create a frame for encryption parameters
        self.params_frame = ctk.CTkFrame(self.encryption_frame)
        self.params_frame.grid(row=3, column=0, padx=10, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        ctk.CTkLabel(self.params_frame, text="Encryption Parameters", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, columnspan=4, sticky=tk.W, padx=5, pady=5)
        
        # Create a frame for Tags
        self.tags_frame = ctk.CTkFrame(self.encryption_frame)
        self.tags_frame.grid(row=3, column=1, padx=10, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        ctk.CTkLabel(self.tags_frame, text="Key Tags", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
        
        ctk.CTkLabel(self.tags_frame, text="Key Name:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.key_name_entry = ctk.CTkEntry(self.tags_frame, width=150)
        self.key_name_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        ctk.CTkLabel(self.tags_frame, text="Tag:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.key_tag_entry = ctk.CTkEntry(self.tags_frame, width=150)
        self.key_tag_entry.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Initial setup for Caesar+Substitution parameters
        self.setup_caesar_params()
        
        # Buttons
        self.encrypt_button = ctk.CTkButton(self.encryption_frame, text="Encrypt", command=self.encrypt_text)
        self.encrypt_button.grid(row=4, column=0, padx=10, pady=10, sticky=tk.W)
        
        self.decrypt_button = ctk.CTkButton(self.encryption_frame, text="Decrypt", command=self.decrypt_text)
        self.decrypt_button.grid(row=4, column=1, padx=10, pady=10, sticky=tk.W)
        
        # Output text area
        ctk.CTkLabel(self.encryption_frame, text="Result:").grid(row=5, column=0, sticky=tk.W, padx=10, pady=5)
        self.output_text = ctk.CTkTextbox(self.encryption_frame, width=400, height=100)
        self.output_text.grid(row=6, column=0, columnspan=2, padx=10, pady=5, sticky=(tk.W, tk.E))
        
        # Save key button
        self.save_key_button = ctk.CTkButton(self.encryption_frame, text="Save Encryption Key", command=self.save_key)
        self.save_key_button.grid(row=7, column=0, padx=10, pady=10, sticky=tk.W)
        
        # Load key button
        self.load_key_button = ctk.CTkButton(self.encryption_frame, text="Load Encryption Key", command=self.load_key)
        self.load_key_button.grid(row=7, column=1, padx=10, pady=10, sticky=tk.W)
        
        # File/Folder encryption section
        file_frame = ctk.CTkFrame(self.encryption_frame)
        file_frame.grid(row=8, column=0, columnspan=2, padx=10, pady=10, sticky=(tk.W, tk.E))
        ctk.CTkLabel(file_frame, text="File & Folder Encryption", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
        
        # File selection
        ctk.CTkLabel(file_frame, text="Selected:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.file_path_var = tk.StringVar()
        ctk.CTkEntry(file_frame, textvariable=self.file_path_var, width=300).grid(row=1, column=1, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        # Browse buttons
        btn_frame = ctk.CTkFrame(file_frame, fg_color="transparent")
        btn_frame.grid(row=2, column=0, columnspan=2, padx=5, pady=5)
        
        ctk.CTkButton(btn_frame, text="Browse File", command=self.browse_file).pack(side=tk.LEFT, padx=5)
        ctk.CTkButton(btn_frame, text="Browse Folder", command=self.browse_folder).pack(side=tk.LEFT, padx=5)
        
        # Action buttons
        action_frame = ctk.CTkFrame(file_frame, fg_color="transparent")
        action_frame.grid(row=3, column=0, columnspan=2, padx=5, pady=5)
        
        ctk.CTkButton(action_frame, text="Encrypt File/Folder", command=self.encrypt_file_folder).pack(side=tk.LEFT, padx=5)
        ctk.CTkButton(action_frame, text="Decrypt File/Folder", command=self.decrypt_file_folder).pack(side=tk.LEFT, padx=5)
    
    def clear_params_frame(self):
        # Clear all widgets from params frame
        for widget in self.params_frame.winfo_children():
            widget.destroy()
    
    def setup_caesar_params(self):
        self.clear_params_frame()
        ctk.CTkLabel(self.params_frame, text="Caesar Shift Value:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.shift_entry = ctk.CTkEntry(self.params_frame, width=50)
        self.shift_entry.insert(0, "3")  # Default shift
        self.shift_entry.grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)
        
        ctk.CTkButton(self.params_frame, text="Randomize", command=self.randomize_caesar, width=100).grid(row=0, column=2, padx=5, pady=5)
        
        # Range settings
        ctk.CTkLabel(self.params_frame, text="Random Range:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        range_frame = ctk.CTkFrame(self.params_frame, fg_color="transparent")
        range_frame.grid(row=1, column=1, columnspan=2, sticky=tk.W, padx=10, pady=5)
        
        ctk.CTkLabel(range_frame, text="Min:").pack(side=tk.LEFT)
        self.caesar_min_entry = ctk.CTkEntry(range_frame, width=40)
        self.caesar_min_entry.insert(0, "1")
        self.caesar_min_entry.pack(side=tk.LEFT, padx=2)
        
        ctk.CTkLabel(range_frame, text="Max:").pack(side=tk.LEFT, padx=(5,0))
        self.caesar_max_entry = ctk.CTkEntry(range_frame, width=40)
        self.caesar_max_entry.insert(0, "25")
        self.caesar_max_entry.pack(side=tk.LEFT, padx=2)

    def setup_vigenere_params(self):
        self.clear_params_frame()
        ctk.CTkLabel(self.params_frame, text="Vigenere Key:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.vigenere_key_entry = ctk.CTkEntry(self.params_frame, width=150)
        self.vigenere_key_entry.insert(0, "SECRET")  # Default key
        self.vigenere_key_entry.grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)
        
        ctk.CTkButton(self.params_frame, text="Randomize", command=self.randomize_vigenere, width=100).grid(row=0, column=2, padx=5, pady=5)
        
        # Length range settings
        ctk.CTkLabel(self.params_frame, text="Random Length:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        length_frame = ctk.CTkFrame(self.params_frame, fg_color="transparent")
        length_frame.grid(row=1, column=1, columnspan=2, sticky=tk.W, padx=10, pady=5)
        
        ctk.CTkLabel(length_frame, text="Min:").pack(side=tk.LEFT)
        self.vigenere_min_entry = ctk.CTkEntry(length_frame, width=40)
        self.vigenere_min_entry.insert(0, "8")
        self.vigenere_min_entry.pack(side=tk.LEFT, padx=2)
        
        ctk.CTkLabel(length_frame, text="Max:").pack(side=tk.LEFT, padx=(5,0))
        self.vigenere_max_entry = ctk.CTkEntry(length_frame, width=40)
        self.vigenere_max_entry.insert(0, "16")
        self.vigenere_max_entry.pack(side=tk.LEFT, padx=2)
        
        # Character set
        ctk.CTkLabel(self.params_frame, text="Characters:").grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        self.vigenere_chars_entry = ctk.CTkEntry(self.params_frame, width=250)
        self.vigenere_chars_entry.insert(0, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        self.vigenere_chars_entry.grid(row=2, column=1, columnspan=2, sticky=tk.W, padx=10, pady=5)

    def setup_aes_params(self):
        self.clear_params_frame()
        ctk.CTkLabel(self.params_frame, text="Password:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.aes_password_entry = ctk.CTkEntry(self.params_frame, width=150, show="*")
        self.aes_password_entry.insert(0, "StrongPassword123")  # Default password
        self.aes_password_entry.grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)
        
        ctk.CTkButton(self.params_frame, text="Randomize", command=self.randomize_aes, width=100).grid(row=0, column=2, padx=5, pady=5)
        ctk.CTkButton(self.params_frame, text="Show/Hide", command=self.toggle_password_visibility, width=100).grid(row=0, column=3, padx=5, pady=5)
        
        # Length setting
        ctk.CTkLabel(self.params_frame, text="Random Length:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        self.aes_length_entry = ctk.CTkEntry(self.params_frame, width=50)
        self.aes_length_entry.insert(0, "16")
        self.aes_length_entry.grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)
        
        # Character types
        ctk.CTkLabel(self.params_frame, text="Include:").grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        char_frame = ctk.CTkFrame(self.params_frame, fg_color="transparent")
        char_frame.grid(row=2, column=1, columnspan=3, sticky=tk.W, padx=10, pady=5)
        
        self.aes_use_letters = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(char_frame, text="Letters", variable=self.aes_use_letters).pack(side=tk.LEFT, padx=5)
        
        self.aes_use_digits = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(char_frame, text="Digits", variable=self.aes_use_digits).pack(side=tk.LEFT, padx=5)
        
        self.aes_use_special = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(char_frame, text="Special", variable=self.aes_use_special).pack(side=tk.LEFT, padx=5)
    
    def on_encryption_type_changed_ctk(self, choice):
        selected_name = choice
        encryption_types = Encription.get_encryption_types()
        
        # Find the matching encryption type
        for enc_type in encryption_types:
            if enc_type["name"] == selected_name:
                self.current_encryption_type = enc_type["value"]
                break
        
        # Setup appropriate parameter fields
        if self.current_encryption_type == Encription.CAESAR_SUBSTITUTION:
            self.setup_caesar_params()
        elif self.current_encryption_type == Encription.VIGENERE:
            self.setup_vigenere_params()
        elif self.current_encryption_type == Encription.AES:
            self.setup_aes_params()
    
    def setup_server_tab(self):
        # Create a frame for the server config
        server_config_frame = ctk.CTkFrame(self.server_frame)
        server_config_frame.grid(row=0, column=0, columnspan=2, padx=10, pady=5, sticky=(tk.W, tk.E))
        ctk.CTkLabel(server_config_frame, text="Server Configuration", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, columnspan=2, sticky=tk.W, padx=10, pady=5)
        
        # Server configuration
        ctk.CTkLabel(server_config_frame, text="Host:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        self.server_host = ctk.CTkEntry(server_config_frame, width=150)
        self.server_host.insert(0, self.get_local_ip())
        self.server_host.grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)
        
        ctk.CTkLabel(server_config_frame, text="Port:").grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        self.server_port = ctk.CTkEntry(server_config_frame, width=80)
        self.server_port.insert(0, "8000")
        self.server_port.grid(row=2, column=1, sticky=tk.W, padx=10, pady=5)
        
        # Start/Stop server buttons
        self.start_server_button = ctk.CTkButton(server_config_frame, text="Start Server", command=self.start_server)
        self.start_server_button.grid(row=3, column=0, padx=10, pady=10, sticky=tk.W)
        
        self.stop_server_button = ctk.CTkButton(server_config_frame, text="Stop Server", command=self.stop_server, state="disabled")
        self.stop_server_button.grid(row=3, column=1, padx=10, pady=10, sticky=tk.W)
        
        
        # Connected clients frame
        clients_frame = ctk.CTkFrame(self.server_frame)
        clients_frame.grid(row=1, column=0, padx=10, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        ctk.CTkLabel(clients_frame, text="Connected Clients", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        
        # Clients list using scrollable frame
        ctk.CTkLabel(clients_frame, text="Select a client:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        
        # Create scrollable frame for clients
        self.clients_scroll_frame = ctk.CTkScrollableFrame(clients_frame, height=120)
        self.clients_scroll_frame.grid(row=2, column=0, padx=10, pady=5, sticky=(tk.W, tk.E))
        
        # Store client buttons and selected client
        self.client_buttons = {}
        self.selected_client = None
        
        # Kick button
        self.kick_button = ctk.CTkButton(clients_frame, text="Kick Selected Client", command=self.kick_selected_client)
        self.kick_button.grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)
        
        # Server message area
        send_frame = ctk.CTkFrame(self.server_frame)
        send_frame.grid(row=1, column=1, padx=10, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        ctk.CTkLabel(send_frame, text="Send Message", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        
        # Message to send
        ctk.CTkLabel(send_frame, text="Message:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        self.server_message = ctk.CTkTextbox(send_frame, width=300, height=60)
        self.server_message.grid(row=2, column=0, padx=10, pady=5, sticky=(tk.W, tk.E))
        
        # Encrypt before sending checkbox
        self.encrypt_server_message = tk.BooleanVar()
        # Encrypt options frame
        encrypt_frame = ctk.CTkFrame(send_frame, fg_color="transparent")
        encrypt_frame.grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)
        
        self.encrypt_server_checkbox = ctk.CTkCheckBox(encrypt_frame, text="Encrypt message", variable=self.encrypt_server_message)
        self.encrypt_server_checkbox.pack(side=tk.LEFT)
        
        ctk.CTkButton(encrypt_frame, text="Load Key", command=self.load_key, width=100).pack(side=tk.LEFT, padx=5)
        
        # Send buttons
        self.send_to_selected_button = ctk.CTkButton(send_frame, text="Send to Selected", command=self.send_to_selected_client)
        self.send_to_selected_button.grid(row=4, column=0, padx=10, pady=5, sticky=tk.W)
        
        self.broadcast_button = ctk.CTkButton(send_frame, text="Broadcast to All", command=self.broadcast_message)
        self.broadcast_button.grid(row=5, column=0, padx=10, pady=5, sticky=tk.W)
        
        # File transfer section (next to send_frame)
        file_transfer_frame = ctk.CTkFrame(self.server_frame)
        file_transfer_frame.grid(row=1, column=2, padx=10, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        ctk.CTkLabel(file_transfer_frame, text="File Transfer", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W, padx=10, pady=5)
        
        self.server_file_path_var = tk.StringVar()
        ctk.CTkEntry(file_transfer_frame, textvariable=self.server_file_path_var, width=200).pack(fill=tk.X, padx=10, pady=2)
        
        file_btn_frame = ctk.CTkFrame(file_transfer_frame, fg_color="transparent")
        file_btn_frame.pack(fill=tk.X, padx=10, pady=2)
        
        ctk.CTkButton(file_btn_frame, text="Browse File", command=lambda: self.browse_file_for_transfer('server'), width=90).pack(side=tk.LEFT, padx=2)
        ctk.CTkButton(file_btn_frame, text="Browse Folder", command=lambda: self.browse_folder_for_transfer('server'), width=90).pack(side=tk.LEFT, padx=2)
        
        ctk.CTkButton(file_transfer_frame, text="Send File/Folder", command=self.send_file_to_client).pack(fill=tk.X, padx=10, pady=2)
        
        # Server log
        log_frame = ctk.CTkFrame(self.server_frame)
        log_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky=(tk.W, tk.E, tk.S))
        ctk.CTkLabel(log_frame, text="Server Log", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W, padx=10, pady=5)
        
        self.server_log = ctk.CTkTextbox(log_frame, width=500, height=150)
        self.server_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Decryption section for Server
        decrypt_frame = ctk.CTkFrame(self.server_frame)
        decrypt_frame.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky=(tk.W, tk.E))
        ctk.CTkLabel(decrypt_frame, text="Manual Decryption", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W, padx=10, pady=5)
        
        ctk.CTkButton(decrypt_frame, text="Decrypt Selected Log Entry", command=lambda: self.decrypt_selected_log_entry(self.server_log, self.server_decrypt_output)).pack(anchor=tk.W, padx=10, pady=5)
        
        self.server_decrypt_output = ctk.CTkTextbox(decrypt_frame, width=500, height=60)
        self.server_decrypt_output.pack(fill=tk.X, padx=10, pady=5)
        
    def setup_client_tab(self):
        # Client configuration
        config_frame = ctk.CTkFrame(self.client_frame)
        config_frame.grid(row=0, column=0, columnspan=2, padx=10, pady=5, sticky=(tk.W, tk.E))
        ctk.CTkLabel(config_frame, text="Client Configuration", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, columnspan=2, sticky=tk.W, padx=10, pady=5)
        
        ctk.CTkLabel(config_frame, text="Server Host:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        self.client_host = ctk.CTkEntry(config_frame, width=150)
        self.client_host.insert(0, self.get_local_ip())
        self.client_host.grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)
        
        ctk.CTkLabel(config_frame, text="Server Port:").grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        self.client_port = ctk.CTkEntry(config_frame, width=80)
        self.client_port.insert(0, "8000")
        self.client_port.grid(row=2, column=1, sticky=tk.W, padx=10, pady=5)
        
        # Connect button
        self.connect_button = ctk.CTkButton(config_frame, text="Connect to Server", command=self.connect_to_server)
        self.connect_button.grid(row=3, column=0, padx=10, pady=10, sticky=tk.W)
        
        self.disconnect_button = ctk.CTkButton(config_frame, text="Disconnect", command=self.disconnect_from_server, state="disabled")
        self.disconnect_button.grid(row=3, column=1, padx=10, pady=10, sticky=tk.W)
        
        # Message section
        message_frame = ctk.CTkFrame(self.client_frame)
        message_frame.grid(row=1, column=0, padx=10, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        ctk.CTkLabel(message_frame, text="Send Message", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        
        # Message to send
        ctk.CTkLabel(message_frame, text="Message:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        self.client_message = ctk.CTkTextbox(message_frame, width=400, height=100)
        self.client_message.grid(row=2, column=0, padx=10, pady=5, sticky=(tk.W, tk.E))
        
        # Encrypt before sending checkbox
        self.encrypt_message = tk.BooleanVar()
        # Encrypt options frame
        encrypt_frame = ctk.CTkFrame(message_frame, fg_color="transparent")
        encrypt_frame.grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)
        
        self.encrypt_checkbox = ctk.CTkCheckBox(encrypt_frame, text="Encrypt message", variable=self.encrypt_message)
        self.encrypt_checkbox.pack(side=tk.LEFT)
        
        ctk.CTkButton(encrypt_frame, text="Load Key", command=self.load_key, width=100).pack(side=tk.LEFT, padx=5)
        
        # Send button
        self.send_button = ctk.CTkButton(message_frame, text="Send Message", command=self.send_message)
        self.send_button.grid(row=4, column=0, padx=10, pady=10, sticky=tk.W)
        
        # File transfer section (next to message_frame)
        file_transfer_frame = ctk.CTkFrame(self.client_frame)
        file_transfer_frame.grid(row=1, column=1, padx=10, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        ctk.CTkLabel(file_transfer_frame, text="File Transfer", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W, padx=10, pady=5)
        
        self.client_file_path_var = tk.StringVar()
        ctk.CTkEntry(file_transfer_frame, textvariable=self.client_file_path_var, width=200).pack(fill=tk.X, padx=10, pady=2)
        
        file_btn_frame = ctk.CTkFrame(file_transfer_frame, fg_color="transparent")
        file_btn_frame.pack(fill=tk.X, padx=10, pady=2)
        
        ctk.CTkButton(file_btn_frame, text="Browse File", command=lambda: self.browse_file_for_transfer('client'), width=90).pack(side=tk.LEFT, padx=2)
        ctk.CTkButton(file_btn_frame, text="Browse Folder", command=lambda: self.browse_folder_for_transfer('client'), width=90).pack(side=tk.LEFT, padx=2)
        
        ctk.CTkButton(file_transfer_frame, text="Send File/Folder", command=self.send_file_to_server).pack(fill=tk.X, padx=10, pady=2)
        
        # Client log
        log_frame = ctk.CTkFrame(self.client_frame)
        log_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky=(tk.W, tk.E))
        ctk.CTkLabel(log_frame, text="Client Log", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W, padx=10, pady=5)
        
        self.client_log = ctk.CTkTextbox(log_frame, width=500, height=150)
        self.client_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Decryption section for Client
        decrypt_frame = ctk.CTkFrame(self.client_frame)
        decrypt_frame.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky=(tk.W, tk.E))
        ctk.CTkLabel(decrypt_frame, text="Manual Decryption", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W, padx=10, pady=5)
        
        ctk.CTkButton(decrypt_frame, text="Decrypt Selected Log Entry", command=lambda: self.decrypt_selected_log_entry(self.client_log, self.client_decrypt_output)).pack(anchor=tk.W, padx=10, pady=5)
        
        self.client_decrypt_output = ctk.CTkTextbox(decrypt_frame, width=500, height=60)
        self.client_decrypt_output.pack(fill=tk.X, padx=10, pady=5)
    
    def decrypt_selected_log_entry(self, log_widget, output_widget):
        try:
            # Get selected text
            try:
                selected_text = log_widget.selection_get()
            except:
                messagebox.showwarning("Warning", "Please select text from the log to decrypt.")
                return
            
            output_widget.delete("1.0", tk.END)
            
            # Try to parse as JSON first (if it's a full message object)
            # Or try to extract from "Message from ...: <JSON>" format
            
            json_text = selected_text
            if "{" in selected_text:
                json_text = selected_text[selected_text.find("{"):]
                if "}" in json_text:
                    json_text = json_text[:json_text.rfind("}")+1]
            
            decrypted_text = None
            success_key = None
            
            # 1. Try treating as self-contained encrypted message
            try:
                msg_data = json.loads(json_text)
                if "encrypted_message" in msg_data and "encryption_data" in msg_data:
                    decrypt_data = {
                        "type": msg_data["encryption_data"]["type"],
                        "text": msg_data["encrypted_message"],
                        "params": msg_data["encryption_data"]["params"]
                    }
                    decrypted_text = Encription.decrypt(decrypt_data)
                    success_key = "Message's own parameters"
            except:
                pass
            
            # 2. If failed, try using keys from encryption_key.json
            if not decrypted_text and os.path.exists("encryption_key.json"):
                try:
                    with open("encryption_key.json", "r") as file:
                        keys_data = json.load(file)
                        
                    keys_list = []
                    if isinstance(keys_data, list):
                        keys_list = keys_data
                    elif isinstance(keys_data, dict):
                        keys_list = [keys_data]
                        
                    # Try each key
                    for i, key_data in enumerate(keys_list):
                        try:
                            # Construct decrypt data using the selected text as the encrypted text
                            # and params from the saved key
                            
                            # Clean up selected text - remove "Message from ...: " prefix if present
                            clean_text = selected_text.strip()
                            if ": " in clean_text:
                                clean_text = clean_text.split(": ", 1)[1]
                                
                            # Also handle if it's inside the JSON structure but we just want the text
                            try:
                                j = json.loads(json_text)
                                if "encrypted_message" in j:
                                    clean_text = j["encrypted_message"]
                            except:
                                pass
                                
                            decrypt_data = {
                                "type": key_data["type"],
                                "text": clean_text,
                                "params": key_data["params"]
                            }
                            
                            # Handle base64 params in key file
                            if "params" in decrypt_data:
                                for k, v in decrypt_data["params"].items():
                                    if k in ["salt", "iv"] and isinstance(v, str):
                                        # Keep as string, let decrypt handle it or convert if needed
                                        pass
                            
                            result = Encription.decrypt(decrypt_data)
                            # If we get here without error, it might be a valid decryption
                            # But for simple ciphers like Caesar, almost anything decrypts.
                            # For AES, it will likely fail if wrong key.
                            
                            decrypted_text = result
                            success_key = f"Key #{i+1} from file"
                            break # Stop at first success
                        except:
                            continue
                except Exception as e:
                    output_widget.insert(tk.END, f"Error reading keys: {str(e)}\n")
            
            if decrypted_text:
                output_widget.insert(tk.END, f"Decrypted ({success_key}): {decrypted_text}")
            else:
                output_widget.insert(tk.END, "Failed to decrypt. No matching key found or invalid format.")
                
        except Exception as e:
            output_widget.insert(tk.END, f"Error: {str(e)}")

    def get_local_ip(self):
        try:
            # Create a socket connection to an external server
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # It doesn't need to be reachable
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"  # Fallback to localhost
    
    def kick_selected_client(self):
        """Kick the selected client from the server"""
        if not self.server_instance:
            messagebox.showwarning("Warning", "Server is not running.")
            return
            
        if not self.selected_client:
            messagebox.showwarning("Warning", "No client selected.")
            return
            
        # Ask for confirmation
        confirm = messagebox.askyesno("Confirm", f"Are you sure you want to kick client {self.selected_client}?")
        if not confirm:
            return
            
        # Kick the client
        success = self.server_instance.kick_client(self.selected_client)
        
        if success:
            self.update_server_log(f"Client {self.selected_client} has been kicked.\n")
            
            # Remove from listbox
            selection = self.clients_listbox.curselection()
            if selection:
                self.clients_listbox.delete(selection[0])
                self.selected_client = None
        else:
            self.update_server_log(f"Failed to kick client {self.selected_client}.\n")
    
    def start_server(self):
        try:
            host = self.server_host.get()
            port = int(self.server_port.get())
            
            self.update_server_log(f"Starting server on {host}:{port}...\n")
            
            # Create and start the server
            self.server_instance = Server(host, port)
            
            # Set a message handler to handle incoming client messages
            self.server_instance.set_message_handler(self.handle_client_message)
            
            # Set handler for client kicks
            self.server_instance.set_client_kicked_handler(self.handle_client_kicked)
            
            # Update UI
            self.start_server_button.configure(state="disabled")
            self.stop_server_button.configure(state="normal")
            
            self.update_server_log("Server started successfully.\n")
        except Exception as e:
            self.update_server_log(f"Server error: {str(e)}\n")
            # Re-enable start button on error
            self.root.after(0, lambda: self.start_server_button.configure(state="normal"))
            self.root.after(0, lambda: self.stop_server_button.configure(state="disabled"))
    
    def handle_client_message(self, client_address, message):
        """Called when a client sends a message to the server"""
        try:
            # Try to parse as JSON to check for file transfer
            try:
                msg_data = json.loads(message)
                if msg_data.get('type') == 'file_transfer':
                    # Handle file transfer
                    self.update_server_log(f"Receiving {msg_data.get('file_type', 'file')} from {client_address}...\n")
                    self.root.after(0, lambda: self.handle_file_transfer(msg_data, source="client"))
                    return
            except:
                pass
            
            # Just log the raw message (encrypted or not)
            self.update_server_log(f"Message from {client_address}: {message}\n")
            
            # Update client list if this is a new client
            client_str = f"{client_address[0]}:{client_address[1]}"
            if client_str not in self.client_buttons:
                self.root.after(0, lambda cs=client_str: self.add_client_to_list(cs))
        except Exception as e:
            self.update_server_log(f"Error handling client message: {str(e)}\n")
    
    def add_client_to_list(self, client_str):
        """Add a client button to the scrollable frame"""
        btn = ctk.CTkButton(
            self.clients_scroll_frame,
            text=client_str,
            command=lambda cs=client_str: self.select_client(cs),
            fg_color="transparent",
            hover_color=("gray70", "gray30"),
            anchor="w"
        )
        btn.pack(fill=tk.X, pady=2)
        self.client_buttons[client_str] = btn
    
    def remove_client_from_list(self, client_str):
        """Remove a client button from the scrollable frame"""
        if client_str in self.client_buttons:
            self.client_buttons[client_str].destroy()
            del self.client_buttons[client_str]
    
    def clear_client_list(self):
        """Clear all client buttons"""
        for widget in self.clients_scroll_frame.winfo_children():
            widget.destroy()
        self.client_buttons.clear()
        self.selected_client = None
    
    def select_client(self, client_str):
        """Select a client from the list"""
        # Highlight selected client
        for cs, btn in self.client_buttons.items():
            if cs == client_str:
                btn.configure(fg_color=("gray75", "gray25"))
            else:
                btn.configure(fg_color="transparent")
        
        # Parse the address (format is "ip:port")
        try:
            ip, port = client_str.split(':')
            port = int(port)
            self.selected_client = (ip, port)
        except:
            self.selected_client = None
    
    def handle_client_kicked(self, client_address, reason):
        """Called when a client is kicked from the server"""
        client_str = f"{client_address[0]}:{client_address[1]}"
        self.update_server_log(f"Client {client_str} kicked: {reason}\n")
        
        # Remove from client list
        if client_str in self.client_buttons:
            self.root.after(0, lambda cs=client_str: self.remove_client_from_list(cs))
    
    def send_to_selected_client(self):
        if not self.server_instance:
            messagebox.showwarning("Warning", "Server is not running.")
            return
            
        if not self.selected_client:
            messagebox.showwarning("Warning", "No client selected.")
            return
            
        message = self.server_message.get("1.0", tk.END).strip()
        if not message:
            messagebox.showwarning("Warning", "No message to send.")
            return
            
        original_message = message
            
        # Check if we need to encrypt the message
        if self.encrypt_server_message.get():
            if not self.current_encryption_type:
                messagebox.showwarning("Warning", "No encryption type selected.")
                return
                
            # Get encryption parameters
            params = self.get_encryption_params()
            if not params:
                return  # Error in parameters
                
            encrypted_result = Encription.encrypt(message, params, self.current_encryption_type)
            
            # Create a JSON message with encrypted text AND encryption data (for decryption)
            message_data = {
                "encrypted_message": encrypted_result["text"],
                "encryption_data": {
                    "type": encrypted_result["type"],
                    "params": encrypted_result["params"]
                }
            }
            
            # Convert to JSON string
            message = json.dumps(message_data)
            
            self.update_server_log(f"Message encrypted before sending (key included but hidden).\n")
            
        # Send the message to the selected client
        client_parts = self.selected_client.split(':')
        client_address = (client_parts[0], int(client_parts[1]))
        
        success = self.server_instance.send_to_client(client_address, message)
        
        if success:
            # Only show the original message in the log (not the encrypted version or key)
            self.update_server_log(f"Message sent to {self.selected_client}: {original_message}\n")
            self.server_message.delete("1.0", tk.END)
        else:
            self.update_server_log(f"Failed to send message to {self.selected_client}.\n")
    
    def broadcast_message(self):
        if not self.server_instance:
            messagebox.showwarning("Warning", "Server is not running.")
            return
            
        message = self.server_message.get("1.0", tk.END).strip()
        if not message:
            messagebox.showwarning("Warning", "No message to send.")
            return
            
        original_message = message
            
        # Check if we need to encrypt the message
        if self.encrypt_server_message.get():
            if not self.current_encryption_type:
                messagebox.showwarning("Warning", "No encryption type selected.")
                return
                
            # Get encryption parameters
            params = self.get_encryption_params()
            if not params:
                return  # Error in parameters
                
            encrypted_result = Encription.encrypt(message, params, self.current_encryption_type)
            
            # Create a JSON message with encrypted text AND encryption data (for decryption)
            message_data = {
                "encrypted_message": encrypted_result["text"],
                "encryption_data": {
                    "type": encrypted_result["type"],
                    "params": encrypted_result["params"]
                }
            }
            
            # Convert to JSON string
            message = json.dumps(message_data)
            
            self.update_server_log(f"Message encrypted before broadcasting (key included but hidden).\n")
            
        # Broadcast the message to all clients
        count = self.server_instance.broadcast(message)
        
        if count is not None and count > 0:
            # Only show the original message in the log (not encrypted version or key)
            self.update_server_log(f"Message broadcast to {count} clients: {original_message}\n")
            self.server_message.delete("1.0", tk.END)
        else:
            self.update_server_log("No clients connected to receive broadcast.\n")
    
    def update_server_log(self, message):
        # This needs to be thread-safe
        self.root.after(0, lambda: self._update_server_log_safe(message))
    
    def _update_server_log_safe(self, message):
        self.server_log.insert(tk.END, message)
    
    def stop_server(self):
        if self.server_instance:
            self.update_server_log("Stopping server...\n")
            self.server_instance.close()
            self.server_instance = None
            
            # Clear the clients listbox
            self.clear_client_list()
        
        # Update UI
        self.start_server_button.configure(state="normal")
        self.stop_server_button.configure(state="disabled")
        self.update_server_log("Server stopped.\n")
    
    def connect_to_server(self):
        try:
            host = self.client_host.get()
            port = int(self.client_port.get())
            
            self.client_log.insert(tk.END, f"Connecting to server at {host}:{port}...\n")
            
            self.client = Client(host, port)
            
            # Set up callback for incoming messages
            self.client.set_message_callback(self.handle_server_message)
            
            # Set up callback for disconnection
            self.client.set_disconnect_callback(self.handle_disconnection)
            
            # Update UI
            self.connect_button.configure(state="disabled")
            self.disconnect_button.configure(state="normal")
            
            self.client_log.insert(tk.END, "Connected successfully!\n")
        except Exception as e:
            self.client_log.insert(tk.END, f"Connection error: {str(e)}\n")
    
    def handle_server_message(self, message):
        """Called when a message is received from the server"""
        try:
            # Try to parse as JSON to check for file transfer
            try:
                msg_data = json.loads(message)
                if msg_data.get('type') == 'file_transfer':
                    # Handle file transfer
                    self.root.after(0, lambda: self._update_client_log_safe(f"Receiving {msg_data.get('file_type', 'file')} from server...\n"))
                    self.root.after(0, lambda: self.handle_file_transfer(msg_data, source="server"))
                    return
            except:
                pass
            
            # Just log the raw message (encrypted or not)
            self.root.after(0, lambda: self._update_client_log_safe(f"Message from server: {message}\n"))
        except Exception as e:
            self.root.after(0, lambda: self._update_client_log_safe(f"Error processing message: {str(e)}\n"))
    
    def handle_disconnection(self, reason):
        """Called when disconnected from the server"""
        self.root.after(0, lambda: self._handle_disconnection_safe(reason))
    
    def _handle_disconnection_safe(self, reason):
        """Thread-safe handler for disconnection"""
        self.client_log.insert(tk.END, f"Disconnected from server: {reason}\n")
        
        # Update UI
        self.connect_button.configure(state="normal")
        self.disconnect_button.configure(state="disabled")
        
        # Clear client reference
        self.client = None
    
    def _update_client_log_safe(self, message):
        self.client_log.insert(tk.END, message)
        self.client_log.see(tk.END)
    
    def disconnect_from_server(self):
        if hasattr(self, 'client') and self.client:
            self.client_log.insert(tk.END, "Disconnecting from server...\n")
            self.client_log.see(tk.END)
            
            self.client.close()
            self.client = None
            
            # Update UI
            self.connect_button.config(state="normal")
            self.disconnect_button.config(state="disabled")
            
            self.client_log.insert(tk.END, "Disconnected.\n")
            self.client_log.see(tk.END)
    
    def send_message(self):
        try:
            if not hasattr(self, 'client') or not self.client:
                messagebox.showwarning("Warning", "Not connected to a server. Please connect first.")
                return
            
            message = self.client_message.get("1.0", tk.END).strip()
            if not message:
                messagebox.showwarning("Warning", "Please enter a message to send.")
                return
            
            original_message = message
            
            # Check if we need to encrypt the message
            if self.encrypt_message.get():
                if not self.current_encryption_type:
                    messagebox.showwarning("Warning", "No encryption type selected.")
                    return
                    
                # Get encryption parameters
                params = self.get_encryption_params()
                if not params:
                    return  # Error in parameters
                    
                encrypted_result = Encription.encrypt(message, params, self.current_encryption_type)
                
                # Create a message with encrypted text AND encryption data (for decryption)
                message_data = {
                    "encrypted_message": encrypted_result["text"],
                    "encryption_data": {
                        "type": encrypted_result["type"],
                        "params": encrypted_result["params"]
                    }
                }
                
                # Convert to JSON
                json_message = json.dumps(message_data)
                
                self.client_log.insert(tk.END, "Message encrypted before sending (key included but hidden).\n")
                self.client_log.see(tk.END)
                
                # Send the encrypted message with encryption data
                success = self.client.send(json_message)
            else:
                # Send as plaintext
                success = self.client.send(message)
            
            if success:
                # Only display the original message text, not the encryption details
                self.client_log.insert(tk.END, f"You: {original_message}\n")
                self.client_log.see(tk.END)
                self.client_message.delete("1.0", tk.END)
            else:
                self.client_log.insert(tk.END, "Failed to send message.\n")
                self.client_log.see(tk.END)
                
        except Exception as e:
            self.client_log.insert(tk.END, f"Error sending message: {str(e)}\n")
            self.client_log.see(tk.END)
    
    def get_encryption_params(self):
        params = {}
        
        if self.current_encryption_type == Encription.CAESAR_SUBSTITUTION:
            try:
                params['shift'] = int(self.shift_entry.get())
            except ValueError:
                messagebox.showerror("Error", "Shift value must be an integer.")
                return None
                
        elif self.current_encryption_type == Encription.VIGENERE:
            key = self.vigenere_key_entry.get()
            if not key:
                messagebox.showerror("Error", "Vigenere key cannot be empty.")
                return None
            params['key'] = key
            
        elif self.current_encryption_type == Encription.AES:
            password = self.aes_password_entry.get()
            if not password:
                messagebox.showerror("Error", "Password cannot be empty.")
                return None
            params['password'] = password
            
        return params
    
    def randomize_caesar(self):
        """Generate random Caesar shift value using range from text boxes"""
        import random
        
        try:
            min_val = int(self.caesar_min_entry.get())
            max_val = int(self.caesar_max_entry.get())
            
            if min_val < 1 or max_val > 25 or min_val > max_val:
                messagebox.showerror("Error", "Invalid range! Min must be 1-25, Max must be >= Min and <= 25")
                return
            
            random_shift = random.randint(min_val, max_val)
            self.shift_entry.delete(0, tk.END)
            self.shift_entry.insert(0, str(random_shift))
            messagebox.showinfo("Randomized", f"Caesar shift set to: {random_shift}\n(Range: {min_val}-{max_val})")
        except ValueError:
            messagebox.showerror("Error", "Please enter valid numbers for range!")

    def randomize_vigenere(self):
        """Generate random Vigenere key using settings from text boxes"""
        import random
        
        try:
            min_len = int(self.vigenere_min_entry.get())
            max_len = int(self.vigenere_max_entry.get())
            characters = self.vigenere_chars_entry.get()
            
            if min_len < 1 or max_len < min_len:
                messagebox.showerror("Error", "Invalid length range! Min must be >= 1, Max must be >= Min")
                return
            
            if not characters:
                messagebox.showerror("Error", "Character set cannot be empty!")
                return
            
            length = random.randint(min_len, max_len)
            random_key = ''.join(random.choices(characters, k=length))
            self.vigenere_key_entry.delete(0, tk.END)
            self.vigenere_key_entry.insert(0, random_key)
            messagebox.showinfo("Randomized", f"Vigenere key set to: {random_key}\n\nLength: {length}\nCharacters used: {len(set(characters))} unique chars")
        except ValueError:
            messagebox.showerror("Error", "Please enter valid numbers for length!")

    def randomize_aes(self):
        """Generate random AES password using settings from checkboxes and text box"""
        import random
        import string
        
        try:
            length = int(self.aes_length_entry.get())
            
            if length < 8 or length > 64:
                messagebox.showerror("Error", "Length must be between 8 and 64!")
                return
            
            # Build character set from checkboxes
            characters = ""
            char_types = []
            
            if self.aes_use_letters.get():
                characters += string.ascii_letters
                char_types.append("letters")
            if self.aes_use_digits.get():
                characters += string.digits
                char_types.append("digits")
            if self.aes_use_special.get():
                characters += string.punctuation
                char_types.append("special chars")
            
            # If no character types selected, use default
            if not characters:
                messagebox.showwarning("Warning", "No character types selected! Using default (all types).")
                characters = string.ascii_letters + string.digits + string.punctuation
                char_types = ["letters", "digits", "special chars"]
            
            random_password = ''.join(random.choices(characters, k=length))
            self.aes_password_entry.delete(0, tk.END)
            self.aes_password_entry.insert(0, random_password)
            
            messagebox.showinfo("Randomized", f"AES password set to:\n{random_password}\n\nLength: {length}\nUsing: {', '.join(char_types)}\n\n⚠️ SAVE THIS PASSWORD!")
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number for length!")
    
    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.aes_password_entry.cget('show') == '*':
            self.aes_password_entry.config(show='')
        else:
            self.aes_password_entry.config(show='*')
    
    def encrypt_text(self):
        try:
            text = self.input_text.get("1.0", tk.END).strip()
            if not text:
                messagebox.showwarning("Warning", "Please enter text to encrypt.")
                return
            
            params = self.get_encryption_params()
            if params is None:
                return  # Error in parameters
            
            self.encryption_result = Encription.encrypt(text, params, self.current_encryption_type)
            
            # Display the encrypted text
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, self.encryption_result["text"])
            
            messagebox.showinfo("Success", "Text encrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def decrypt_text(self):
        try:
            if not self.encryption_result:
                messagebox.showwarning("Warning", "No encryption data available. Please encrypt something first or load a key.")
                return
            
            encrypted_text = self.input_text.get("1.0", tk.END).strip()
            if not encrypted_text:
                messagebox.showwarning("Warning", "Please enter text to decrypt.")
                return
            
            # Update the encryption result with the new text (in case it was modified)
            self.encryption_result["text"] = encrypted_text
            
            # Decrypt using the stored encryption parameters
            decrypted_text = Encription.decrypt(self.encryption_result)
            
            # Display the decrypted text
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, decrypted_text)
            
            messagebox.showinfo("Success", "Text decrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    
    def save_key(self):
        if not self.encryption_result:
            messagebox.showwarning("Warning", "No encryption data to save. Encrypt text first.")
            return
        
        try:
            from tkinter import simpledialog
            import time
            import os
            import json
            import base64
            
            # Get key name and tag from input fields
            key_name = self.key_name_entry.get().strip()
            if not key_name:
                messagebox.showwarning("Warning", "Please enter a Key Name in the Tags section.")
                return
                
            key_tag = self.key_tag_entry.get().strip()
            
            # Make a copy to handle bytes values
            result_copy = dict(self.encryption_result)
            result_copy["key_name"] = key_name
            result_copy["key_tag"] = key_tag
            result_copy["saved_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            
            # Convert bytes to base64 strings for storage
            if "params" in result_copy:
                params_copy = dict(result_copy["params"])
                
                for key, value in params_copy.items():
                    if isinstance(value, bytes):
                        params_copy[key] = base64.b64encode(value).decode('utf-8')
                
                result_copy["params"] = params_copy
            
            # Load existing keys if file exists
            existing_data = []
            if os.path.exists("encryption_key.json"):
                try:
                    with open("encryption_key.json", "r") as file:
                        data = json.load(file)
                        if isinstance(data, list):
                            existing_data = data
                        elif isinstance(data, dict):
                            existing_data = [data]
                except:
                    pass # Start fresh if file is corrupt
            
            # Check if name exists
            for i, key in enumerate(existing_data):
                if key.get("key_name") == key_name:
                    if messagebox.askyesno("Overwrite", f"Key '{key_name}' already exists. Overwrite?"):
                        existing_data[i] = result_copy
                        break
                    else:
                        return
            else:
                # Append new key
                existing_data.append(result_copy)
            
            with open("encryption_key.json", "w") as file:
                json.dump(existing_data, file, indent=4)
                
            messagebox.showinfo("Success", f"Key '{key_name}' saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save key: {str(e)}")
    
    def load_key(self):
        try:
            import os
            import json
            import base64
            from tkinter import simpledialog
            
            if not os.path.exists("encryption_key.json"):
                messagebox.showwarning("Warning", "No saved key found.")
                return
            
            with open("encryption_key.json", "r") as file:
                data = json.load(file)
            
            keys_list = []
            if isinstance(data, dict):
                keys_list = [data]
            elif isinstance(data, list):
                keys_list = data
            
            if not keys_list:
                messagebox.showwarning("Warning", "Key file is empty.")
                return
            
            # Create selection dialog
            select_window = tk.Toplevel(self.root)
            select_window.title("Manage Keys")
            select_window.geometry("600x450")
            
            ttk.Label(select_window, text="Select a key:").pack(pady=10)
            
            # Listbox with scrollbar
            list_frame = ttk.Frame(select_window)
            list_frame.pack(fill=tk.BOTH, expand=True, padx=10)
            
            scrollbar = ttk.Scrollbar(list_frame)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            key_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, width=60, height=15)
            key_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.config(command=key_listbox.yview)
            
            def refresh_list():
                key_listbox.delete(0, tk.END)
                for i, key in enumerate(keys_list):
                    name = key.get("key_name", f"Key #{i+1}")
                    tag = key.get("key_tag", "")
                    algo = "Unknown"
                    if key.get("type") == Encription.CAESAR_SUBSTITUTION: algo = "Caesar"
                    elif key.get("type") == Encription.VIGENERE: algo = "Vigenere"
                    elif key.get("type") == Encription.AES: algo = "AES"
                    
                    display_text = f"{name} [{algo}]"
                    if tag:
                        display_text += f" - Tag: {tag}"
                    
                    key_listbox.insert(tk.END, display_text)
            
            refresh_list()
            
            def save_changes():
                with open("encryption_key.json", "w") as file:
                    json.dump(keys_list, file, indent=4)
            
            def load_selected():
                selection = key_listbox.curselection()
                if not selection:
                    messagebox.showwarning("Warning", "Please select a key.")
                    return
                
                index = selection[0]
                selected_data = keys_list[index]
                
                # Convert base64 strings back to bytes if needed
                if "params" in selected_data:
                    for key, value in selected_data["params"].items():
                        if key in ["salt", "iv"] and isinstance(value, str):
                            try:
                                selected_data["params"][key] = base64.b64decode(value)
                            except:
                                pass # Keep as string if decode fails
                
                self.encryption_result = selected_data
                
                # Update Name and Tag fields
                self.key_name_entry.delete(0, tk.END)
                self.key_name_entry.insert(0, selected_data.get("key_name", ""))
                
                self.key_tag_entry.delete(0, tk.END)
                self.key_tag_entry.insert(0, selected_data.get("key_tag", ""))
                
                # Update UI parameters
                encryption_type = selected_data.get("type")
                self.encryption_type_var.set(encryption_type)
                self.on_encryption_type_changed(None)
                
                if encryption_type == Encription.CAESAR_SUBSTITUTION:
                    self.setup_caesar_params()
                    self.shift_entry.delete(0, tk.END)
                    self.shift_entry.insert(0, str(selected_data.get("params", {}).get("shift", 3)))
                    
                elif encryption_type == Encription.VIGENERE:
                    self.setup_vigenere_params()
                    self.vigenere_key_entry.delete(0, tk.END)
                    self.vigenere_key_entry.insert(0, selected_data.get("params", {}).get("key", "SECRET"))
                    
                elif encryption_type == Encription.AES:
                    self.setup_aes_params()
                    self.aes_password_entry.delete(0, tk.END)
                    self.aes_password_entry.insert(0, selected_data.get("params", {}).get("password", "StrongPassword123"))
                
                messagebox.showinfo("Success", f"Key '{selected_data.get('key_name', 'Selected')}' loaded!")
                select_window.destroy()
            
            def delete_selected():
                selection = key_listbox.curselection()
                if not selection:
                    messagebox.showwarning("Warning", "Please select a key to delete.")
                    return
                
                index = selection[0]
                key_name = keys_list[index].get("key_name", f"Key #{index+1}")
                
                if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete '{key_name}'?"):
                    del keys_list[index]
                    save_changes()
                    refresh_list()
            
            def edit_selected():
                selection = key_listbox.curselection()
                if not selection:
                    messagebox.showwarning("Warning", "Please select a key to edit.")
                    return
                
                index = selection[0]
                key_data = keys_list[index]
                
                new_name = simpledialog.askstring("Edit Key", "Enter new name:", initialvalue=key_data.get("key_name", ""))
                if new_name:
                    key_data["key_name"] = new_name
                    
                new_tag = simpledialog.askstring("Edit Key", "Enter new tag:", initialvalue=key_data.get("key_tag", ""))
                if new_tag is not None:
                    key_data["key_tag"] = new_tag
                
                save_changes()
                refresh_list()
            
            # Buttons
            btn_frame = ttk.Frame(select_window)
            btn_frame.pack(pady=10)
            
            ttk.Button(btn_frame, text="Load Key", command=load_selected).pack(side=tk.LEFT, padx=5)
            ttk.Button(btn_frame, text="Edit Key", command=edit_selected).pack(side=tk.LEFT, padx=5)
            ttk.Button(btn_frame, text="Delete Key", command=delete_selected).pack(side=tk.LEFT, padx=5)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load key: {str(e)}")

    def setup_hashing_tab(self):
        # Initialize hashing instance with dummy data to access methods
        self.hasher = Hashing("")
        self.hash_types = self.hasher.get_hash_types()
        self.current_hash_type = "sha256"
        
        # Input section
        input_frame = ctk.CTkFrame(self.hashing_frame)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ctk.CTkLabel(input_frame, text="Enter text to hash:").pack(anchor=tk.W, padx=10, pady=5)
        self.hash_input_text = ctk.CTkTextbox(input_frame, width=400, height=100)
        self.hash_input_text.pack(fill=tk.X, padx=10, pady=5)
        
        # File selection
        file_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        file_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.hash_file_path_var = tk.StringVar()
        self.hash_file_entry = ctk.CTkEntry(file_frame, textvariable=self.hash_file_path_var)
        self.hash_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ctk.CTkButton(file_frame, text="Browse File...", command=self.browse_hash_file).pack(side=tk.LEFT, padx=5)
        
        # Options section
        options_frame = ctk.CTkFrame(self.hashing_frame)
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ctk.CTkLabel(options_frame, text="Hash Algorithm:").pack(side=tk.LEFT, padx=10, pady=5)
        self.hash_type_combo = ctk.CTkComboBox(options_frame, values=self.hash_types, command=self.on_hash_type_change_ctk)
        self.hash_type_combo.set("sha256")
        self.hash_type_combo.pack(side=tk.LEFT, padx=10, pady=5)
        
        # Actions
        action_frame = ctk.CTkFrame(self.hashing_frame, fg_color="transparent")
        action_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ctk.CTkButton(action_frame, text="Hash Text", command=self.hash_text).pack(side=tk.LEFT, padx=10)
        ctk.CTkButton(action_frame, text="Hash File", command=self.hash_file).pack(side=tk.LEFT, padx=10)
        
        # Output section
        output_frame = ctk.CTkFrame(self.hashing_frame)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        ctk.CTkLabel(output_frame, text="Output:").pack(anchor=tk.W, padx=10, pady=5)
        self.hash_output_text = ctk.CTkTextbox(output_frame, width=400, height=100)
        self.hash_output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def setup_cracking_tab(self):
        # Input section
        input_frame = ctk.CTkFrame(self.cracking_frame)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ctk.CTkLabel(input_frame, text="Hash to Crack:").pack(anchor=tk.W, padx=10, pady=5)
        self.crack_input_text = ctk.CTkEntry(input_frame, width=400)
        self.crack_input_text.pack(fill=tk.X, padx=10, pady=5)
        
        # Options section
        options_frame = ctk.CTkFrame(self.cracking_frame)
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ctk.CTkLabel(options_frame, text="Hash Algorithm:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.crack_hash_type_combo = ctk.CTkComboBox(options_frame, values=self.hasher.get_hash_types())
        self.crack_hash_type_combo.set("sha256")
        self.crack_hash_type_combo.grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)
        
        ctk.CTkLabel(options_frame, text="Max Length:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        self.crack_max_length = ctk.CTkEntry(options_frame, width=50)
        self.crack_max_length.insert(0, "4")
        self.crack_max_length.grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)
        
        ctk.CTkLabel(options_frame, text="Charset:").grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        self.crack_charset = ctk.CTkEntry(options_frame, width=300)
        self.crack_charset.insert(0, "abcdefghijklmnopqrstuvwxyz0123456789")
        self.crack_charset.grid(row=2, column=1, sticky=tk.W, padx=10, pady=5)
        
        # Actions
        action_frame = ctk.CTkFrame(self.cracking_frame, fg_color="transparent")
        action_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ctk.CTkButton(action_frame, text="Estimate Time", command=self.estimate_crack_time).pack(side=tk.LEFT, padx=10)
        ctk.CTkButton(action_frame, text="Start Cracking", command=self.start_cracking).pack(side=tk.LEFT, padx=10)
        
        # Output section
        output_frame = ctk.CTkFrame(self.cracking_frame)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        ctk.CTkLabel(output_frame, text="Output:").pack(anchor=tk.W, padx=10, pady=5)
        self.crack_output_text = ctk.CTkTextbox(output_frame, width=400, height=100)
        self.crack_output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def estimate_crack_time(self):
        try:
            length = int(self.crack_max_length.get())
            charset = self.crack_charset.get()
            charset_size = len(charset)
            hash_type = self.crack_hash_type_combo.get()
            
            self.crack_output_text.insert(tk.END, "Benchmarking...\n")
            self.root.update()
            
            hashrate = self.hasher.benchmark(hash_type, 0.5) # 0.5s benchmark
            
            self.crack_output_text.insert(tk.END, f"Hashrate: {hashrate:.2f} hashes/sec\n")
            
            total_seconds = 0
            for l in range(1, length + 1):
                total_seconds += self.hasher.estimate_time(l, charset_size, hashrate)
            
            # Format time
            if total_seconds < 60:
                time_str = f"{total_seconds:.2f} seconds"
            elif total_seconds < 3600:
                time_str = f"{total_seconds/60:.2f} minutes"
            elif total_seconds < 86400:
                time_str = f"{total_seconds/3600:.2f} hours"
            else:
                time_str = f"{total_seconds/86400:.2f} days"
                
            self.crack_output_text.insert(tk.END, f"Estimated time for length 1-{length}: {time_str}\n")
            self.crack_output_text.see(tk.END)
            
        except Exception as e:
            messagebox.showerror("Error", f"Estimation failed: {str(e)}")

    def start_cracking(self):
        target_hash = self.crack_input_text.get().strip()
        if not target_hash:
            messagebox.showwarning("Warning", "Please enter a hash to crack.")
            return
            
        try:
            length = int(self.crack_max_length.get())
            charset = self.crack_charset.get()
            hash_type = self.crack_hash_type_combo.get()
            
            self.crack_output_text.insert(tk.END, f"Starting crack for {hash_type} hash: {target_hash}\n")
            self.crack_output_text.insert(tk.END, "Please wait...\n")
            self.root.update()
            
            # Run in a separate thread to avoid freezing UI
            def crack_thread():
                start_time = time.time()
                result = self.hasher.crack_bruteforce(target_hash, hash_type, length, charset)
                elapsed = time.time() - start_time
                
                self.root.after(0, lambda: self.display_crack_result(result, elapsed))
            
            Thread(target=crack_thread, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Cracking failed: {str(e)}")

    def display_crack_result(self, result, elapsed):
        if result:
            self.crack_output_text.insert(tk.END, f"SUCCESS! Found match: '{result}'\n")
        else:
            self.crack_output_text.insert(tk.END, "FAILED. No match found within parameters.\n")
        
        self.crack_output_text.insert(tk.END, f"Time taken: {elapsed:.2f} seconds\n")
        self.crack_output_text.see(tk.END)
        messagebox.showinfo("Cracking Complete", f"Result: {result if result else 'Not found'}")

    def browse_hash_file(self):
        from tkinter import filedialog
        filename = filedialog.askopenfilename()
        if filename:
            self.hash_file_path_var.set(filename)
            
    def on_hash_type_change_ctk(self, choice):
        self.current_hash_type = choice
        
    def hash_text(self):
        text = self.hash_input_text.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Warning", "Please enter text to hash.")
            return
            
        try:
            result = self.hasher.hash(text, self.current_hash_type)
            self.display_hash_result(result)
        except Exception as e:
            messagebox.showerror("Error", f"Hashing failed: {str(e)}")
            
    def hash_file(self):
        file_path = self.hash_file_path_var.get()
        if not file_path:
            messagebox.showwarning("Warning", "Please select a file first.")
            return
            
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "File not found.")
            return
            
        try:
            # Using the hashing_file method from Hashing class
            result = self.hasher.hashing_file(file_path, self.current_hash_type)
            self.display_hash_result(result)
        except Exception as e:
            messagebox.showerror("Error", f"File hashing failed: {str(e)}")
            
    def display_hash_result(self, result):
        self.hash_output_text.delete("1.0", tk.END)
        self.hash_output_text.insert(tk.END, result)
    
    # File/Folder encryption methods
    def browse_file(self):
        from tkinter import filedialog
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path_var.set(filename)
    
    def browse_folder(self):
        from tkinter import filedialog
        folder = filedialog.askdirectory()
        if folder:
            self.file_path_var.set(folder)
    
    def browse_file_for_transfer(self, source):
        from tkinter import filedialog
        filename = filedialog.askopenfilename()
        if filename:
            if source == 'server':
                self.server_file_path_var.set(filename)
            else:
                self.client_file_path_var.set(filename)
    
    def browse_folder_for_transfer(self, source):
        from tkinter import filedialog
        folder = filedialog.askdirectory()
        if folder:
            if source == 'server':
                self.server_file_path_var.set(folder)
            else:
                self.client_file_path_var.set(folder)
    
    def encrypt_file_folder(self):
        path = self.file_path_var.get()
        if not path:
            messagebox.showwarning("Warning", "Please select a file or folder first.")
            return
        
        if not os.path.exists(path):
            messagebox.showerror("Error", "Path does not exist.")
            return
        
        params = self.get_encryption_params()
        if params is None:
            return
        
        try:
            # Get the directory where the script is running
            script_dir = os.path.dirname(os.path.abspath(__file__))
            
            if os.path.isfile(path):
                # Create encrypted_files directory
                encrypted_files_dir = os.path.join(script_dir, "encrypted_files")
                os.makedirs(encrypted_files_dir, exist_ok=True)
                
                # Copy file to encrypted_files directory
                filename = os.path.basename(path)
                dest_path = os.path.join(encrypted_files_dir, filename)
                
                import shutil
                shutil.copy2(path, dest_path)
                
                # Encrypt the copied file
                encrypted_result = Encription.encrypt_file(dest_path, params, self.current_encryption_type)
                
                # Save encrypted data as .enc file
                enc_filename = filename + ".enc"
                enc_path = os.path.join(encrypted_files_dir, enc_filename)
                
                with open(enc_path, 'w') as f:
                    json.dump(encrypted_result, f, indent=4)
                
                # Remove the unencrypted copy
                os.remove(dest_path)
                
                messagebox.showinfo("Success", f"File encrypted and saved to:\n{enc_path}")
            else:
                # Create encrypted_folders directory
                encrypted_folders_dir = os.path.join(script_dir, "encrypted_folders")
                os.makedirs(encrypted_folders_dir, exist_ok=True)
                
                # Get folder name
                folder_name = os.path.basename(path)
                dest_folder = os.path.join(encrypted_folders_dir, folder_name)
                
                # Copy entire folder structure
                import shutil
                if os.path.exists(dest_folder):
                    shutil.rmtree(dest_folder)
                shutil.copytree(path, dest_folder)
                
                # Encrypt all files in the folder
                encrypted_files = []
                for root, dirs, files in os.walk(dest_folder):
                    for file in files:
                        file_path = os.path.join(root, file)
                        
                        # Encrypt each file
                        encrypted_result = Encription.encrypt_file(file_path, params, self.current_encryption_type)
                        
                        # Save as .enc file
                        enc_path = file_path + ".enc"
                        with open(enc_path, 'w') as f:
                            json.dump(encrypted_result, f, indent=4)
                        
                        # Remove original file
                        os.remove(file_path)
                        encrypted_files.append(os.path.relpath(enc_path, dest_folder))
                
                # Create a zip of the encrypted folder
                zip_path = dest_folder + ".zip"
                shutil.make_archive(dest_folder, 'zip', dest_folder)
                
                # Remove the unzipped folder
                shutil.rmtree(dest_folder)
                
                messagebox.showinfo("Success", f"Folder encrypted ({len(encrypted_files)} files) and saved to:\n{zip_path}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def decrypt_file_folder(self):
        from tkinter import filedialog
        import shutil
        
        # Get the directory where the script is running
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Ask user to select encrypted file or folder
        choice = messagebox.askquestion("Decrypt", "Are you decrypting a folder?\n\nYes = Folder (zip)\nNo = Single File")
        
        try:
            if choice == 'yes':
                # Decrypt folder
                zip_file = filedialog.askopenfilename(
                    title="Select encrypted folder (zip)",
                    filetypes=[("ZIP files", "*.zip"), ("All files", "*.*")]
                )
                
                if not zip_file:
                    return
                
                # Create decrypted_folders directory
                decrypted_folders_dir = os.path.join(script_dir, "decrypted_folders")
                os.makedirs(decrypted_folders_dir, exist_ok=True)
                
                # Extract zip to temp location
                temp_extract = os.path.join(script_dir, "temp_decrypt")
                if os.path.exists(temp_extract):
                    shutil.rmtree(temp_extract)
                
                shutil.unpack_archive(zip_file, temp_extract)
                
                # Store encryption info from first file
                encryption_info = None
                
                # Decrypt all .enc files
                for root, dirs, files in os.walk(temp_extract):
                    for file in files:
                        if file.endswith('.enc'):
                            enc_path = os.path.join(root, file)
                            
                            # Load encrypted data
                            with open(enc_path, 'r') as f:
                                encrypted_result = json.load(f)
                            
                            # Save encryption info from first file
                            if encryption_info is None:
                                encryption_info = {
                                    "encryption_type": encrypted_result.get('type'),
                                    "encryption_type_name": self.get_encryption_type_name(encrypted_result.get('type')),
                                    "params": encrypted_result.get('params', {})
                                }
                            
                            # Decrypt to original filename
                            original_name = encrypted_result.get('filename', file[:-4])
                            output_path = os.path.join(root, original_name)
                            
                            Encription.decrypt_file(encrypted_result, output_path)
                            
                            # Remove .enc file
                            os.remove(enc_path)
                
                # Move to decrypted_folders directory
                folder_name = os.path.basename(zip_file)[:-4]  # Remove .zip
                final_dest = os.path.join(decrypted_folders_dir, folder_name)
                
                # If folder exists, add number suffix
                if os.path.exists(final_dest):
                    counter = 1
                    base_name = folder_name
                    while os.path.exists(final_dest):
                        folder_name = f"{base_name}_{counter}"
                        final_dest = os.path.join(decrypted_folders_dir, folder_name)
                        counter += 1
                
                shutil.move(temp_extract, final_dest)
                
                # Save key.json in the decrypted folder
                if encryption_info:
                    key_file = os.path.join(final_dest, "key.json")
                    with open(key_file, 'w') as f:
                        json.dump(encryption_info, f, indent=4)
                
                messagebox.showinfo("Success", f"Folder decrypted to:\n{final_dest}\n\nEncryption info saved in key.json")
            else:
                # Decrypt single file
                enc_file = filedialog.askopenfilename(
                    title="Select encrypted file",
                    filetypes=[("Encrypted files", "*.enc"), ("JSON files", "*.json"), ("All files", "*.*")]
                )
                
                if not enc_file:
                    return
                
                # Create decrypted_files directory
                decrypted_files_dir = os.path.join(script_dir, "decrypted_files")
                os.makedirs(decrypted_files_dir, exist_ok=True)
                
                try:
                    # Load encrypted data
                    with open(enc_file, 'r') as f:
                        encrypted_result = json.load(f)
                    
                    # Check if we need to supply password/key from loaded key
                    if self.encryption_result:
                        # If file is missing params or password, try to use loaded key
                        if 'params' not in encrypted_result:
                            encrypted_result['params'] = {}
                            
                        # For AES
                        if encrypted_result.get('type') == Encription.AES:
                            if 'password' not in encrypted_result['params']:
                                if self.encryption_result.get('type') == Encription.AES:
                                    loaded_pass = self.encryption_result.get('params', {}).get('password')
                                    if loaded_pass:
                                        encrypted_result['params']['password'] = loaded_pass
                        
                        # For Vigenere
                        elif encrypted_result.get('type') == Encription.VIGENERE:
                            if 'key' not in encrypted_result['params']:
                                if self.encryption_result.get('type') == Encription.VIGENERE:
                                    loaded_key = self.encryption_result.get('params', {}).get('key')
                                    if loaded_key:
                                        encrypted_result['params']['key'] = loaded_key
                        
                        # For Caesar
                        elif encrypted_result.get('type') == Encription.CAESAR_SUBSTITUTION:
                            if 'shift' not in encrypted_result['params']:
                                if self.encryption_result.get('type') == Encription.CAESAR_SUBSTITUTION:
                                    loaded_shift = self.encryption_result.get('params', {}).get('shift')
                                    if loaded_shift:
                                        encrypted_result['params']['shift'] = loaded_shift

                    # Get original filename
                    default_name = encrypted_result.get('filename', 'decrypted_file')
                    
                    # Create a folder for this file
                    base_name = os.path.splitext(default_name)[0]
                    file_folder = os.path.join(decrypted_files_dir, base_name)
                    
                    # If folder exists, add number suffix
                    if os.path.exists(file_folder):
                        counter = 1
                        original_base = base_name
                        while os.path.exists(file_folder):
                            base_name = f"{original_base}_{counter}"
                            file_folder = os.path.join(decrypted_files_dir, base_name)
                            counter += 1
                    
                    os.makedirs(file_folder, exist_ok=True)
                    
                    # Decrypt
                    output_path = os.path.join(file_folder, default_name)
                    Encription.decrypt_file(encrypted_result, output_path)
                    
                    # Save encryption info as key.json
                    encryption_info = {
                        "encryption_type": encrypted_result.get('type'),
                        "encryption_type_name": self.get_encryption_type_name(encrypted_result.get('type')),
                        "params": encrypted_result.get('params', {}),
                        "original_filename": default_name,
                        "original_size": encrypted_result.get('original_size')
                    }
                    
                    key_file = os.path.join(file_folder, "key.json")
                    with open(key_file, 'w') as f:
                        json.dump(encryption_info, f, indent=4)
                    
                    messagebox.showinfo("Success", f"File decrypted to:\n{file_folder}\n\nFile: {default_name}\nEncryption info: key.json")
                    
                except json.JSONDecodeError:
                    messagebox.showerror("Error", "Failed to read file. It might not be a valid JSON/Encrypted file.\n\nMake sure you selected the .json or .enc file created by this app.")
                except Exception as e:
                    messagebox.showerror("Error", f"Decryption failed: {str(e)}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    
    def get_encryption_type_name(self, type_value):
        """Get human-readable encryption type name"""
        type_names = {
            1: "Caesar+Substitution Cipher",
            2: "Vigenère Cipher",
            3: "AES Encryption"
        }
        return type_names.get(type_value, "Unknown")
    
    def send_file_to_client(self):
        if not self.server_instance:
            messagebox.showwarning("Warning", "Server is not running.")
            return
        
        if not self.selected_client:
            messagebox.showwarning("Warning", "No client selected.")
            return
        
        path = self.server_file_path_var.get()
        if not path or not os.path.exists(path):
            messagebox.showwarning("Warning", "Please select a valid file or folder.")
            return
        
        try:
            params = self.get_encryption_params()
            if params is None:
                return
            
            script_dir = os.path.dirname(os.path.abspath(__file__))
            import shutil
            
            if os.path.isfile(path):
                # Create encrypted_files directory
                encrypted_files_dir = os.path.join(script_dir, "encrypted_files")
                os.makedirs(encrypted_files_dir, exist_ok=True)
                
                # Copy and encrypt file
                filename = os.path.basename(path)
                dest_path = os.path.join(encrypted_files_dir, filename)
                shutil.copy2(path, dest_path)
                
                encrypted_result = Encription.encrypt_file(dest_path, params, self.current_encryption_type)
                
                # Save as .enc
                enc_path = os.path.join(encrypted_files_dir, filename + ".enc")
                with open(enc_path, 'w') as f:
                    json.dump(encrypted_result, f, indent=4)
                
                os.remove(dest_path)
                
                # Send the encrypted file
                message_data = {
                    "type": "file_transfer",
                    "file_type": "file",
                    "encrypted_data": encrypted_result
                }
                
                file_type = "file"
            else:
                # Create encrypted_folders directory
                encrypted_folders_dir = os.path.join(script_dir, "encrypted_folders")
                os.makedirs(encrypted_folders_dir, exist_ok=True)
                
                # Copy folder
                folder_name = os.path.basename(path)
                dest_folder = os.path.join(encrypted_folders_dir, folder_name)
                
                if os.path.exists(dest_folder):
                    shutil.rmtree(dest_folder)
                shutil.copytree(path, dest_folder)
                
                # Encrypt all files
                encrypted_files_list = []
                for root, dirs, files in os.walk(dest_folder):
                    for file in files:
                        file_path = os.path.join(root, file)
                        encrypted_result = Encription.encrypt_file(file_path, params, self.current_encryption_type)
                        
                        enc_path = file_path + ".enc"
                        with open(enc_path, 'w') as f:
                            json.dump(encrypted_result, f, indent=4)
                        
                        os.remove(file_path)
                        encrypted_files_list.append(encrypted_result)
                
                # Zip the encrypted folder
                zip_path = dest_folder + ".zip"
                shutil.make_archive(dest_folder, 'zip', dest_folder)
                shutil.rmtree(dest_folder)
                
                # Read zip as base64 for transmission
                with open(zip_path, 'rb') as f:
                    zip_data = base64.b64encode(f.read()).decode('utf-8')
                
                message_data = {
                    "type": "file_transfer",
                    "file_type": "folder",
                    "folder_name": folder_name,
                    "zip_data": zip_data,
                    "encrypted_files": encrypted_files_list
                }
                
                file_type = "folder"
            
            # Send to selected client
            client_parts = self.selected_client.split(':')
            client_address = (client_parts[0], int(client_parts[1]))
            
            success = self.server_instance.send_to_client(client_address, json.dumps(message_data))
            
            if success:
                filename = encrypted_result.get('filename', folder_name if file_type == "folder" else 'unknown')
                self.update_server_log(f"Sent encrypted {file_type}: {filename} to {self.selected_client}\n")
            else:
                self.update_server_log(f"Failed to send {file_type}\n")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send file: {str(e)}")
    
    def send_file_to_server(self):
        if not hasattr(self, 'client') or not self.client:
            messagebox.showwarning("Warning", "Not connected to server.")
            return
        
        path = self.client_file_path_var.get()
        if not path or not os.path.exists(path):
            messagebox.showwarning("Warning", "Please select a valid file or folder.")
            return
        
        try:
            params = self.get_encryption_params()
            if params is None:
                return
            
            script_dir = os.path.dirname(os.path.abspath(__file__))
            import shutil
            
            if os.path.isfile(path):
                # Create encrypted_files directory
                encrypted_files_dir = os.path.join(script_dir, "encrypted_files")
                os.makedirs(encrypted_files_dir, exist_ok=True)
                
                # Copy and encrypt file
                filename = os.path.basename(path)
                dest_path = os.path.join(encrypted_files_dir, filename)
                shutil.copy2(path, dest_path)
                
                encrypted_result = Encription.encrypt_file(dest_path, params, self.current_encryption_type)
                
                # Save as .enc
                enc_path = os.path.join(encrypted_files_dir, filename + ".enc")
                with open(enc_path, 'w') as f:
                    json.dump(encrypted_result, f, indent=4)
                
                os.remove(dest_path)
                
                # Send the encrypted file
                message_data = {
                    "type": "file_transfer",
                    "file_type": "file",
                    "encrypted_data": encrypted_result
                }
                
                file_type = "file"
            else:
                # Create encrypted_folders directory
                encrypted_folders_dir = os.path.join(script_dir, "encrypted_folders")
                os.makedirs(encrypted_folders_dir, exist_ok=True)
                
                # Copy folder
                folder_name = os.path.basename(path)
                dest_folder = os.path.join(encrypted_folders_dir, folder_name)
                
                if os.path.exists(dest_folder):
                    shutil.rmtree(dest_folder)
                shutil.copytree(path, dest_folder)
                
                # Encrypt all files
                encrypted_files_list = []
                for root, dirs, files in os.walk(dest_folder):
                    for file in files:
                        file_path = os.path.join(root, file)
                        encrypted_result = Encription.encrypt_file(file_path, params, self.current_encryption_type)
                        
                        enc_path = file_path + ".enc"
                        with open(enc_path, 'w') as f:
                            json.dump(encrypted_result, f, indent=4)
                        
                        os.remove(file_path)
                        encrypted_files_list.append(encrypted_result)
                
                # Zip the encrypted folder
                zip_path = dest_folder + ".zip"
                shutil.make_archive(dest_folder, 'zip', dest_folder)
                shutil.rmtree(dest_folder)
                
                # Read zip as base64 for transmission
                with open(zip_path, 'rb') as f:
                    zip_data = base64.b64encode(f.read()).decode('utf-8')
                
                message_data = {
                    "type": "file_transfer",
                    "file_type": "folder",
                    "folder_name": folder_name,
                    "zip_data": zip_data,
                    "encrypted_files": encrypted_files_list
                }
                
                file_type = "folder"
            
            # Send to server
            success = self.client.send(json.dumps(message_data))
            
            if success:
                filename = encrypted_result.get('filename', folder_name if file_type == "folder" else 'unknown')
                self.client_log.insert(tk.END, f"Sent encrypted {file_type}: {filename}\n")
                self.client_log.see(tk.END)
            else:
                self.client_log.insert(tk.END, f"Failed to send {file_type}\n")
                self.client_log.see(tk.END)
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send file: {str(e)}")
    
    def handle_file_transfer(self, message_data, source="server"):
        """Handle incoming file transfers"""
        from tkinter import filedialog
        import shutil
        
        try:
            file_type = message_data.get('file_type', 'file')
            script_dir = os.path.dirname(os.path.abspath(__file__))
            
            if file_type == 'folder':
                # Handle folder transfer
                folder_name = message_data.get('folder_name', 'received_folder')
                zip_data = message_data.get('zip_data', '')
                
                # Create decrypted_folders directory
                decrypted_folders_dir = os.path.join(script_dir, "decrypted_folders")
                os.makedirs(decrypted_folders_dir, exist_ok=True)
                
                # Decode zip data
                zip_bytes = base64.b64decode(zip_data)
                
                # Save to temp zip file
                temp_zip = os.path.join(script_dir, "temp_received.zip")
                
                with open(temp_zip, 'wb') as f:
                    f.write(zip_bytes)
                
                # Extract
                temp_extract = os.path.join(script_dir, "temp_extract")
                if os.path.exists(temp_extract):
                    shutil.rmtree(temp_extract)
                
                shutil.unpack_archive(temp_zip, temp_extract)
                os.remove(temp_zip)
                
                # Store encryption info from first file
                encryption_info = None
                
                # Decrypt all .enc files
                for root, dirs, files in os.walk(temp_extract):
                    for file in files:
                        if file.endswith('.enc'):
                            enc_path = os.path.join(root, file)
                            
                            with open(enc_path, 'r') as f:
                                encrypted_result = json.load(f)
                            
                            # Save encryption info from first file
                            if encryption_info is None:
                                encryption_info = {
                                    "encryption_type": encrypted_result.get('type'),
                                    "encryption_type_name": self.get_encryption_type_name(encrypted_result.get('type')),
                                    "params": encrypted_result.get('params', {})
                                }
                            
                            original_name = encrypted_result.get('filename', file[:-4])
                            output_path = os.path.join(root, original_name)
                            
                            Encription.decrypt_file(encrypted_result, output_path)
                            os.remove(enc_path)
                
                # Move to decrypted_folders directory
                final_dest = os.path.join(decrypted_folders_dir, folder_name)
                
                # If folder exists, add number suffix
                if os.path.exists(final_dest):
                    counter = 1
                    base_name = folder_name
                    while os.path.exists(final_dest):
                        final_dest = os.path.join(decrypted_folders_dir, f"{base_name}_{counter}")
                        counter += 1
                
                shutil.move(temp_extract, final_dest)
                
                # Save key.json in the decrypted folder
                if encryption_info:
                    key_file = os.path.join(final_dest, "key.json")
                    with open(key_file, 'w') as f:
                        json.dump(encryption_info, f, indent=4)
                
                if source == "server":
                    self.client_log.insert(tk.END, f"Received and decrypted folder: {folder_name}\nSaved to: {final_dest}\nEncryption info: key.json\n")
                    self.client_log.see(tk.END)
                else:
                    self.update_server_log(f"Received and decrypted folder: {folder_name}\nSaved to: {final_dest}\nEncryption info: key.json\n")
            else:
                # Handle single file transfer
                encrypted_data = message_data.get('encrypted_data', {})
                filename = encrypted_data.get('filename', 'received_file')
                
                # Create decrypted_files directory
                decrypted_files_dir = os.path.join(script_dir, "decrypted_files")
                os.makedirs(decrypted_files_dir, exist_ok=True)
                
                # Create a folder for this file
                base_name = os.path.splitext(filename)[0]
                file_folder = os.path.join(decrypted_files_dir, base_name)
                
                # If folder exists, add number suffix
                if os.path.exists(file_folder):
                    counter = 1
                    original_base = base_name
                    while os.path.exists(file_folder):
                        base_name = f"{original_base}_{counter}"
                        file_folder = os.path.join(decrypted_files_dir, base_name)
                        counter += 1
                
                os.makedirs(file_folder, exist_ok=True)
                
                # Save decrypted file inside the folder
                output_path = os.path.join(file_folder, filename)
                Encription.decrypt_file(encrypted_data, output_path)
                
                # Save encryption info as key.json
                encryption_info = {
                    "encryption_type": encrypted_data.get('type'),
                    "encryption_type_name": self.get_encryption_type_name(encrypted_data.get('type')),
                    "params": encrypted_data.get('params', {}),
                    "original_filename": filename,
                    "original_size": encrypted_data.get('original_size')
                }
                
                key_file = os.path.join(file_folder, "key.json")
                with open(key_file, 'w') as f:
                    json.dump(encryption_info, f, indent=4)
                
                if source == "server":
                    self.client_log.insert(tk.END, f"Received and decrypted file: {filename}\nSaved to: {file_folder}\nEncryption info: key.json\n")
                    self.client_log.see(tk.END)
                else:
                    self.update_server_log(f"Received and decrypted file: {filename}\nSaved to: {file_folder}\nEncryption info: key.json\n")
        
        except Exception as e:
            error_msg = f"Failed to receive file: {str(e)}\n"
            if source == "server":
                self.client_log.insert(tk.END, error_msg)
                self.client_log.see(tk.END)
            else:
                self.update_server_log(error_msg)
    
    # Fast Connect Helper Methods
    def load_fc_data(self):
        """Load Fast Connect data"""
        try:
            data_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fc_data.json")
            if os.path.exists(data_file):
                with open(data_file, 'r') as f:
                    self.fc_data = json.load(f)
                # Ensure new keys exist
                if "server_ip" not in self.fc_data: self.fc_data["server_ip"] = "127.0.0.1"
                if "friends" not in self.fc_data: self.fc_data["friends"] = []
            else:
                self.fc_data = {
                    "username": "",
                    "server_ip": "127.0.0.1",
                    "friends": [] # List of friend usernames
                }
        except:
            self.fc_data = {"username": "", "server_ip": "127.0.0.1", "friends": []}

    def save_fc_data(self):
        """Save Fast Connect data"""
        try:
            data_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fc_data.json")
            with open(data_file, 'w') as f:
                json.dump(self.fc_data, f, indent=4)
        except Exception as e:
            print(f"Error saving data: {e}")

    # Fast Connect Tab
    def setup_fast_connect_tab(self):
        """Setup the Fast Connect tab with Central Server UI"""
        
        # Initialize variables
        self.load_fc_data()
        self.fc_socket = None
        self.fc_connected = False
        self.fc_current_chat = None # Username
        self.fc_chat_histories = {} # {username: [messages]}
        
        # Main Container - Split View using CTk Frames
        main_container = ctk.CTkFrame(self.fast_connect_frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left Panel (Sidebar)
        left_panel = ctk.CTkFrame(main_container, width=250)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 5))
        left_panel.pack_propagate(False)
        
        # Right Panel (Chat)
        right_panel = ctk.CTkFrame(main_container)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # === Left Panel Content ===
        
        # 1. Server Connection
        server_frame = ctk.CTkFrame(left_panel)
        server_frame.pack(fill=tk.X, pady=(0, 10), padx=5)
        ctk.CTkLabel(server_frame, text="Connection", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W, padx=5, pady=5)
        
        ctk.CTkLabel(server_frame, text="Server IP:").pack(anchor=tk.W, padx=5)
        self.fc_server_ip = ctk.CTkEntry(server_frame)
        self.fc_server_ip.insert(0, self.fc_data.get("server_ip", "127.0.0.1"))
        self.fc_server_ip.pack(fill=tk.X, pady=2, padx=5)
        
        self.fc_connect_btn = ctk.CTkButton(server_frame, text="Connect", command=self.fc_toggle_connection)
        self.fc_connect_btn.pack(fill=tk.X, pady=2, padx=5)
        
        self.fc_status_lbl = ctk.CTkLabel(server_frame, text="Status: Offline", text_color="gray")
        self.fc_status_lbl.pack(anchor=tk.W, padx=5)

        # 2. Profile
        profile_frame = ctk.CTkFrame(left_panel)
        profile_frame.pack(fill=tk.X, pady=(0, 10), padx=5)
        ctk.CTkLabel(profile_frame, text="My Profile", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W, padx=5, pady=5)
        
        ctk.CTkLabel(profile_frame, text="Username:").pack(anchor=tk.W, padx=5)
        self.fc_username_entry = ctk.CTkEntry(profile_frame)
        self.fc_username_entry.insert(0, self.fc_data.get("username", ""))
        self.fc_username_entry.pack(fill=tk.X, pady=2, padx=5)
        self.fc_username_entry.bind("<FocusOut>", self.fc_save_settings)
        
        # 3. Friends List
        friends_frame = ctk.CTkFrame(left_panel)
        friends_frame.pack(fill=tk.BOTH, expand=True, padx=5)
        ctk.CTkLabel(friends_frame, text="Friends", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W, padx=5, pady=5)
        
        # Add Friend Area
        add_frame = ctk.CTkFrame(friends_frame, fg_color="transparent")
        add_frame.pack(fill=tk.X, pady=(0, 5), padx=5)
        self.fc_add_entry = ctk.CTkEntry(add_frame)
        self.fc_add_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ctk.CTkButton(add_frame, text="+", width=30, command=self.fc_add_friend).pack(side=tk.RIGHT)
        
        # Friends list using scrollable frame
        self.fc_friends_scroll = ctk.CTkScrollableFrame(friends_frame)
        self.fc_friends_scroll.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Store friend buttons
        self.fc_friend_buttons = {}
        
        # === Right Panel Content ===
        
        # Header
        self.fc_chat_header = ctk.CTkLabel(right_panel, text="Select a friend to chat", font=("Segoe UI", 14, "bold"))
        self.fc_chat_header.pack(fill=tk.X, pady=(5, 10), padx=10)
        
        # Chat Log
        self.fc_chat_log = ctk.CTkTextbox(right_panel, state="disabled")
        self.fc_chat_log.pack(fill=tk.BOTH, expand=True, pady=(0, 10), padx=10)
        
        # Input Area
        input_frame = ctk.CTkFrame(right_panel, fg_color="transparent")
        input_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.fc_msg_entry = ctk.CTkEntry(input_frame)
        self.fc_msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.fc_msg_entry.bind("<Return>", lambda e: self.fc_send_message())
        
        self.fc_send_btn = ctk.CTkButton(input_frame, text="Send", command=self.fc_send_message, state="disabled", width=80)
        self.fc_send_btn.pack(side=tk.RIGHT)
        
        self.fc_refresh_friends_list()

    # === Logic ===
    
    def fc_save_settings(self, event=None):
        self.fc_data["username"] = self.fc_username_entry.get().strip()
        self.fc_data["server_ip"] = self.fc_server_ip.get().strip()
        self.save_fc_data()

    def fc_toggle_connection(self):
        if self.fc_connected:
            # Disconnect
            self.fc_connected = False
            if self.fc_socket:
                self.fc_socket.close()
            self.fc_status_lbl.config(text="Status: Offline", foreground="gray")
            self.fc_connect_btn.config(text="Connect")
            self.fc_log_system("Disconnected from server.")
        else:
            # Connect
            ip = self.fc_server_ip.get().strip()
            username = self.fc_username_entry.get().strip()
            
            if not username:
                messagebox.showwarning("Warning", "Please enter a username first.")
                return
                
            try:
                self.fc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.fc_socket.connect((ip, 9999))
                self.fc_connected = True
                
                # Start listener
                threading.Thread(target=self.fc_listen_loop, daemon=True).start()
                
                # Send Login
                self.fc_send_json({"type": "login", "username": username})
                
                self.fc_status_lbl.config(text="Status: Connected", foreground="#10b981")
                self.fc_connect_btn.config(text="Disconnect")
                self.fc_save_settings()
                
            except Exception as e:
                self.fc_connected = False
                messagebox.showerror("Error", f"Could not connect to {ip}:9999\n{e}")

    def fc_listen_loop(self):
        while self.fc_connected:
            try:
                message = self.fc_socket.recv(4096).decode('utf-8')
                if not message: break
                
                data = json.loads(message)
                self.root.after(0, lambda: self.fc_handle_incoming(data))
            except:
                break
        
        if self.fc_connected: # If loop broke but we thought we were connected
            self.fc_connected = False
            self.root.after(0, lambda: self.fc_status_lbl.config(text="Status: Disconnected", foreground="red"))
            self.root.after(0, lambda: self.fc_connect_btn.config(text="Connect"))

    def fc_handle_incoming(self, data):
        msg_type = data.get("type")
        
        if msg_type == "chat":
            sender = data.get("sender")
            text = data.get("message")
            self.fc_add_to_history(sender, f"{sender}: {text}")
            if self.fc_current_chat == sender:
                self.fc_refresh_chat()
            
            # Auto-add to friends list if not there?
            if sender not in self.fc_data["friends"]:
                self.fc_data["friends"].append(sender)
                self.fc_refresh_friends_list()
                self.save_fc_data()
                
        elif msg_type == "system":
            msg = data.get("message")
            self.fc_log_system(msg)

    def fc_add_friend(self):
        target = self.fc_add_entry.get().strip()
        if target:
            if target not in self.fc_data["friends"]:
                self.fc_data["friends"].append(target)
                self.save_fc_data()
                self.fc_refresh_friends_list()
            
            # Send request to server (to link/notify)
            if self.fc_connected:
                self.fc_send_json({"type": "add_friend", "target": target})
            
            self.fc_add_entry.delete(0, tk.END)

    def fc_refresh_friends_list(self):
        # Clear existing buttons
        for widget in self.fc_friends_scroll.winfo_children():
            widget.destroy()
        self.fc_friend_buttons.clear()
        
        # Add friend buttons
        for friend in self.fc_data["friends"]:
            btn = ctk.CTkButton(
                self.fc_friends_scroll,
                text=friend,
                command=lambda f=friend: self.fc_select_friend(f),
                fg_color="transparent",
                hover_color=("gray70", "gray30"),
                anchor="w"
            )
            btn.pack(fill=tk.X, pady=2)
            self.fc_friend_buttons[friend] = btn

    def fc_select_friend(self, friend):
        # Highlight selected friend
        for f, btn in self.fc_friend_buttons.items():
            if f == friend:
                btn.configure(fg_color=("gray75", "gray25"))
            else:
                btn.configure(fg_color="transparent")
        
        self.fc_current_chat = friend
        self.fc_chat_header.configure(text=f"Chat with {friend}")
        self.fc_send_btn.configure(state="normal")
        self.fc_refresh_chat()

    def fc_refresh_chat(self):
        self.fc_chat_log.configure(state="normal")
        self.fc_chat_log.delete("1.0", tk.END)
        
        if self.fc_current_chat in self.fc_chat_histories:
            for msg in self.fc_chat_histories[self.fc_current_chat]:
                self.fc_chat_log.insert(tk.END, msg + "\n")
        
        self.fc_chat_log.configure(state="disabled")

    def fc_add_to_history(self, chat_id, message):
        if chat_id not in self.fc_chat_histories:
            self.fc_chat_histories[chat_id] = []
        self.fc_chat_histories[chat_id].append(message)

    def fc_send_message(self):
        text = self.fc_msg_entry.get().strip()
        if not text or not self.fc_current_chat: return
        
        if not self.fc_connected:
            self.fc_log_system("Not connected to server.")
            return
            
        target = self.fc_current_chat
        self.fc_send_json({"type": "chat", "target": target, "message": text})
        
        self.fc_add_to_history(target, f"You: {text}")
        self.fc_refresh_chat()
        self.fc_msg_entry.delete(0, tk.END)

    def fc_send_json(self, data):
        try:
            self.fc_socket.send(json.dumps(data).encode('utf-8'))
        except:
            pass

    def fc_log_system(self, msg):
        # Log to current chat or general log
        if self.fc_current_chat:
            self.fc_add_to_history(self.fc_current_chat, f"[System]: {msg}")
            self.fc_refresh_chat()
        else:
            # Maybe show in status or a popup?
            pass

    def auto_start_services(self):
        """Auto-start services"""
        # Auto-connect if username and IP exist?
        pass


if __name__ == "__main__":
    root = ctk.CTk()
    app = EncryptionApp(root)
    root.after(1000, app.auto_start_services)
    root.mainloop()

