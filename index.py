import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from Files.main import Encription
from Files.server import Server
from Files.client import Client
from threading import Thread
import socket
import json
import os
import base64
from Files.hash import Hashing

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
        style = ttk.Style()
        style.theme_use('clam')
        
        # Color scheme
        bg_dark = "#0f172a"
        surface = "#1e293b"
        surface_hover = "#334155"
        primary = "#3b82f6"
        primary_hover = "#2563eb"
        accent = "#10b981"
        text_primary = "#f8fafc"
        text_secondary = "#94a3b8"
        
        # Configure Notebook (tabs)
        style.configure('TNotebook', background=bg_dark, borderwidth=0)
        style.configure('TNotebook.Tab', 
                       background=surface,
                       foreground=text_secondary,
                       padding=[20, 10],
                       font=('Segoe UI', 10, 'bold'))
        style.map('TNotebook.Tab',
                 background=[('selected', primary)],
                 foreground=[('selected', text_primary)])
        
        # Configure Frames
        style.configure('TFrame', background=bg_dark)
        style.configure('TLabelframe', 
                       background=bg_dark,
                       foreground=text_primary,
                       bordercolor=surface_hover,
                       font=('Segoe UI', 10, 'bold'))
        style.configure('TLabelframe.Label', 
                       background=bg_dark,
                       foreground=primary,
                       font=('Segoe UI', 10, 'bold'))
        
        # Configure Labels
        style.configure('TLabel',
                       background=bg_dark,
                       foreground=text_secondary,
                       font=('Segoe UI', 10))
        
        # Configure Buttons
        style.configure('TButton',
                       background=primary,
                       foreground=text_primary,
                       borderwidth=0,
                       focuscolor='none',
                       font=('Segoe UI', 10, 'bold'),
                       padding=[15, 8])
        style.map('TButton',
                 background=[('active', primary_hover), ('pressed', primary_hover)],
                 foreground=[('active', text_primary)])
        
        # Configure Entry
        style.configure('TEntry',
                       fieldbackground=surface,
                       foreground=text_primary,
                       bordercolor=surface_hover,
                       insertcolor=text_primary,
                       font=('Segoe UI', 10))
        
        # Configure Combobox
        style.configure('TCombobox',
                       fieldbackground=surface,
                       background=surface,
                       foreground=text_primary,
                       arrowcolor=text_primary,
                       bordercolor=surface_hover,
                       font=('Segoe UI', 10))
        style.map('TCombobox',
                 fieldbackground=[('readonly', surface)],
                 selectbackground=[('readonly', primary)])
        
        # Configure Checkbutton
        style.configure('TCheckbutton',
                       background=bg_dark,
                       foreground=text_secondary,
                       font=('Segoe UI', 10))
        
        # Configure text widgets colors
        self.root.option_add('*Text.background', surface)
        self.root.option_add('*Text.foreground', text_primary)
        self.root.option_add('*Text.insertBackground', text_primary)
        self.root.option_add('*Text.font', 'Consolas 10')
        
        # Configure Listbox
        self.root.option_add('*Listbox.background', surface)
        self.root.option_add('*Listbox.foreground', text_primary)
        self.root.option_add('*Listbox.selectBackground', primary)
        self.root.option_add('*Listbox.selectForeground', text_primary)
        self.root.option_add('*Listbox.font', 'Segoe UI 10')
    
    def create_ui(self):
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.encryption_frame = ttk.Frame(self.notebook)
        self.hashing_frame = ttk.Frame(self.notebook)
        self.cracking_frame = ttk.Frame(self.notebook)
        self.server_frame = ttk.Frame(self.notebook)
        self.client_frame = ttk.Frame(self.notebook)
        self.fast_connect_frame = ttk.Frame(self.notebook)
        
        self.notebook.add(self.encryption_frame, text="Encryption")
        self.notebook.add(self.hashing_frame, text="Hashing")
        self.notebook.add(self.cracking_frame, text="Cracking")
        self.notebook.add(self.server_frame, text="Server")
        self.notebook.add(self.client_frame, text="Client")
        self.notebook.add(self.fast_connect_frame, text="Fast Connect")
        
        # Set up each tab
        self.setup_encryption_tab()
        self.setup_hashing_tab()
        self.setup_cracking_tab()
        self.setup_server_tab()
        self.setup_client_tab()
        self.setup_fast_connect_tab()
    
    def setup_encryption_tab(self):
        # Input text area
        ttk.Label(self.encryption_frame, text="Enter text to encrypt:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.input_text = scrolledtext.ScrolledText(self.encryption_frame, width=40, height=5)
        self.input_text.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky=(tk.W, tk.E))
        
        # Encryption type selection
        ttk.Label(self.encryption_frame, text="Encryption Method:").grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        
        # Create combobox for encryption types
        self.encryption_type_var = tk.StringVar()
        self.encryption_type_combo = ttk.Combobox(self.encryption_frame, textvariable=self.encryption_type_var, state="readonly")
        encryption_types = Encription.get_encryption_types()
        self.encryption_type_combo['values'] = [t["name"] for t in encryption_types]
        self.encryption_type_combo.current(0)  # Set default to first option
        self.encryption_type_combo.grid(row=2, column=1, sticky=tk.W, padx=10, pady=5)
        self.encryption_type_combo.bind('<<ComboboxSelected>>', self.on_encryption_type_changed)
        
        # Create a frame for encryption parameters
        self.params_frame = ttk.LabelFrame(self.encryption_frame, text="Encryption Parameters")
        self.params_frame.grid(row=3, column=0, padx=10, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create a frame for Tags
        self.tags_frame = ttk.LabelFrame(self.encryption_frame, text="Key Tags")
        self.tags_frame.grid(row=3, column=1, padx=10, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(self.tags_frame, text="Key Name:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.key_name_entry = ttk.Entry(self.tags_frame, width=20)
        self.key_name_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(self.tags_frame, text="Tag:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.key_tag_entry = ttk.Entry(self.tags_frame, width=20)
        self.key_tag_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Initial setup for Caesar+Substitution parameters
        self.setup_caesar_params()
        
        # Buttons
        self.encrypt_button = ttk.Button(self.encryption_frame, text="Encrypt", command=self.encrypt_text)
        self.encrypt_button.grid(row=4, column=0, padx=10, pady=10, sticky=tk.W)
        
        self.decrypt_button = ttk.Button(self.encryption_frame, text="Decrypt", command=self.decrypt_text)
        self.decrypt_button.grid(row=4, column=1, padx=10, pady=10, sticky=tk.W)
        
        # Output text area
        ttk.Label(self.encryption_frame, text="Result:").grid(row=5, column=0, sticky=tk.W, padx=10, pady=5)
        self.output_text = scrolledtext.ScrolledText(self.encryption_frame, width=40, height=5)
        self.output_text.grid(row=6, column=0, columnspan=2, padx=10, pady=5, sticky=(tk.W, tk.E))
        
        # Save key button
        self.save_key_button = ttk.Button(self.encryption_frame, text="Save Encryption Key", command=self.save_key)
        self.save_key_button.grid(row=7, column=0, padx=10, pady=10, sticky=tk.W)
        
        # Load key button
        self.load_key_button = ttk.Button(self.encryption_frame, text="Load Encryption Key", command=self.load_key)
        self.load_key_button.grid(row=7, column=1, padx=10, pady=10, sticky=tk.W)
        
        # File/Folder encryption section
        file_frame = ttk.LabelFrame(self.encryption_frame, text="File & Folder Encryption")
        file_frame.grid(row=8, column=0, columnspan=2, padx=10, pady=10, sticky=(tk.W, tk.E))
        
        # File selection
        ttk.Label(file_frame, text="Selected:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.file_path_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_path_var, width=40).grid(row=0, column=1, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        # Browse buttons
        btn_frame = ttk.Frame(file_frame)
        btn_frame.grid(row=1, column=0, columnspan=2, padx=5, pady=5)
        
        ttk.Button(btn_frame, text="Browse File", command=self.browse_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Browse Folder", command=self.browse_folder).pack(side=tk.LEFT, padx=2)
        
        # Action buttons
        action_frame = ttk.Frame(file_frame)
        action_frame.grid(row=2, column=0, columnspan=2, padx=5, pady=5)
        
        ttk.Button(action_frame, text="Encrypt File/Folder", command=self.encrypt_file_folder).pack(side=tk.LEFT, padx=2)
        ttk.Button(action_frame, text="Decrypt File/Folder", command=self.decrypt_file_folder).pack(side=tk.LEFT, padx=2)
    
    def clear_params_frame(self):
        # Clear all widgets from params frame
        for widget in self.params_frame.winfo_children():
            widget.destroy()
    
    def setup_caesar_params(self):
        self.clear_params_frame()
        ttk.Label(self.params_frame, text="Caesar Shift Value:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.shift_entry = ttk.Entry(self.params_frame, width=5)
        self.shift_entry.insert(0, "3")  # Default shift
        self.shift_entry.grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)
        
        ttk.Button(self.params_frame, text="Randomize", command=self.randomize_caesar).grid(row=0, column=2, padx=5, pady=5)
        
        # Range settings
        ttk.Label(self.params_frame, text="Random Range:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        range_frame = ttk.Frame(self.params_frame)
        range_frame.grid(row=1, column=1, columnspan=2, sticky=tk.W, padx=10, pady=5)
        
        ttk.Label(range_frame, text="Min:").pack(side=tk.LEFT)
        self.caesar_min_entry = ttk.Entry(range_frame, width=4)
        self.caesar_min_entry.insert(0, "1")
        self.caesar_min_entry.pack(side=tk.LEFT, padx=2)
        
        ttk.Label(range_frame, text="Max:").pack(side=tk.LEFT, padx=(5,0))
        self.caesar_max_entry = ttk.Entry(range_frame, width=4)
        self.caesar_max_entry.insert(0, "25")
        self.caesar_max_entry.pack(side=tk.LEFT, padx=2)

    def setup_vigenere_params(self):
        self.clear_params_frame()
        ttk.Label(self.params_frame, text="Vigenere Key:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.vigenere_key_entry = ttk.Entry(self.params_frame, width=20)
        self.vigenere_key_entry.insert(0, "SECRET")  # Default key
        self.vigenere_key_entry.grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)
        
        ttk.Button(self.params_frame, text="Randomize", command=self.randomize_vigenere).grid(row=0, column=2, padx=5, pady=5)
        
        # Length range settings
        ttk.Label(self.params_frame, text="Random Length:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        length_frame = ttk.Frame(self.params_frame)
        length_frame.grid(row=1, column=1, columnspan=2, sticky=tk.W, padx=10, pady=5)
        
        ttk.Label(length_frame, text="Min:").pack(side=tk.LEFT)
        self.vigenere_min_entry = ttk.Entry(length_frame, width=4)
        self.vigenere_min_entry.insert(0, "8")
        self.vigenere_min_entry.pack(side=tk.LEFT, padx=2)
        
        ttk.Label(length_frame, text="Max:").pack(side=tk.LEFT, padx=(5,0))
        self.vigenere_max_entry = ttk.Entry(length_frame, width=4)
        self.vigenere_max_entry.insert(0, "16")
        self.vigenere_max_entry.pack(side=tk.LEFT, padx=2)
        
        # Character set
        ttk.Label(self.params_frame, text="Characters:").grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        self.vigenere_chars_entry = ttk.Entry(self.params_frame, width=30)
        self.vigenere_chars_entry.insert(0, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        self.vigenere_chars_entry.grid(row=2, column=1, columnspan=2, sticky=tk.W, padx=10, pady=5)

    def setup_aes_params(self):
        self.clear_params_frame()
        ttk.Label(self.params_frame, text="Password:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.aes_password_entry = ttk.Entry(self.params_frame, width=20, show="*")
        self.aes_password_entry.insert(0, "StrongPassword123")  # Default password
        self.aes_password_entry.grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)
        
        ttk.Button(self.params_frame, text="Randomize", command=self.randomize_aes).grid(row=0, column=2, padx=5, pady=5)
        ttk.Button(self.params_frame, text="Show/Hide", command=self.toggle_password_visibility).grid(row=0, column=3, padx=5, pady=5)
        
        # Length setting
        ttk.Label(self.params_frame, text="Random Length:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        self.aes_length_entry = ttk.Entry(self.params_frame, width=5)
        self.aes_length_entry.insert(0, "16")
        self.aes_length_entry.grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)
        
        # Character types
        ttk.Label(self.params_frame, text="Include:").grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        char_frame = ttk.Frame(self.params_frame)
        char_frame.grid(row=2, column=1, columnspan=3, sticky=tk.W, padx=10, pady=5)
        
        self.aes_use_letters = tk.BooleanVar(value=True)
        ttk.Checkbutton(char_frame, text="Letters", variable=self.aes_use_letters).pack(side=tk.LEFT, padx=5)
        
        self.aes_use_digits = tk.BooleanVar(value=True)
        ttk.Checkbutton(char_frame, text="Digits", variable=self.aes_use_digits).pack(side=tk.LEFT, padx=5)
        
        self.aes_use_special = tk.BooleanVar(value=True)
        ttk.Checkbutton(char_frame, text="Special", variable=self.aes_use_special).pack(side=tk.LEFT, padx=5)
    
    def on_encryption_type_changed(self, event):
        selected_name = self.encryption_type_var.get()
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
        server_config_frame = ttk.LabelFrame(self.server_frame, text="Server Configuration")
        server_config_frame.grid(row=0, column=0, columnspan=2, padx=10, pady=5, sticky=(tk.W, tk.E))
        
        # Server configuration
        ttk.Label(server_config_frame, text="Host:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.server_host = ttk.Entry(server_config_frame, width=15)
        self.server_host.insert(0, self.get_local_ip())
        self.server_host.grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)
        
        ttk.Label(server_config_frame, text="Port:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        self.server_port = ttk.Entry(server_config_frame, width=5)
        self.server_port.insert(0, "8000")
        self.server_port.grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)
        
        # Start/Stop server buttons
        self.start_server_button = ttk.Button(server_config_frame, text="Start Server", command=self.start_server)
        self.start_server_button.grid(row=2, column=0, padx=10, pady=10, sticky=tk.W)
        
        self.stop_server_button = ttk.Button(server_config_frame, text="Stop Server", command=self.stop_server, state="disabled")
        self.stop_server_button.grid(row=2, column=1, padx=10, pady=10, sticky=tk.W)
        
        # Connected clients frame
        clients_frame = ttk.LabelFrame(self.server_frame, text="Connected Clients")
        clients_frame.grid(row=1, column=0, padx=10, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Clients listbox
        ttk.Label(clients_frame, text="Select a client:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.clients_listbox = tk.Listbox(clients_frame, height=5)
        self.clients_listbox.grid(row=1, column=0, padx=10, pady=5, sticky=(tk.W, tk.E))
        self.clients_listbox.bind('<<ListboxSelect>>', self.on_client_selected)
        
        # Kick button
        self.kick_button = ttk.Button(clients_frame, text="Kick Selected Client", command=self.kick_selected_client)
        self.kick_button.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
        
        # Server message area
        send_frame = ttk.LabelFrame(self.server_frame, text="Send Message")
        send_frame.grid(row=1, column=1, padx=10, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Message to send
        ttk.Label(send_frame, text="Message:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.server_message = scrolledtext.ScrolledText(send_frame, width=30, height=3)
        self.server_message.grid(row=1, column=0, padx=10, pady=5, sticky=(tk.W, tk.E))
        
        # Encrypt before sending checkbox
        self.encrypt_server_message = tk.BooleanVar()
        # Encrypt options frame
        encrypt_frame = ttk.Frame(send_frame)
        encrypt_frame.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
        
        self.encrypt_server_checkbox = ttk.Checkbutton(encrypt_frame, text="Encrypt message", variable=self.encrypt_server_message)
        self.encrypt_server_checkbox.pack(side=tk.LEFT)
        
        ttk.Button(encrypt_frame, text="Load Key", command=self.load_key).pack(side=tk.LEFT, padx=5)
        
        # Send buttons
        self.send_to_selected_button = ttk.Button(send_frame, text="Send to Selected", command=self.send_to_selected_client)
        self.send_to_selected_button.grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)
        
        self.broadcast_button = ttk.Button(send_frame, text="Broadcast to All", command=self.broadcast_message)
        self.broadcast_button.grid(row=4, column=0, padx=10, pady=5, sticky=tk.W)
        
        # File transfer section (next to send_frame)
        file_transfer_frame = ttk.LabelFrame(self.server_frame, text="File Transfer")
        file_transfer_frame.grid(row=1, column=2, padx=10, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.server_file_path_var = tk.StringVar()
        ttk.Entry(file_transfer_frame, textvariable=self.server_file_path_var, width=25).pack(fill=tk.X, padx=5, pady=2)
        
        file_btn_frame = ttk.Frame(file_transfer_frame)
        file_btn_frame.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Button(file_btn_frame, text="Browse File", command=lambda: self.browse_file_for_transfer('server')).pack(side=tk.LEFT, padx=2)
        ttk.Button(file_btn_frame, text="Browse Folder", command=lambda: self.browse_folder_for_transfer('server')).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(file_transfer_frame, text="Send File/Folder", command=self.send_file_to_client).pack(fill=tk.X, padx=5, pady=2)
        
        # Server log
        log_frame = ttk.LabelFrame(self.server_frame, text="Server Log")
        log_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky=(tk.W, tk.E, tk.S))
        
        self.server_log = scrolledtext.ScrolledText(log_frame, width=50, height=10)
        self.server_log.grid(row=0, column=0, padx=10, pady=5, sticky=(tk.W, tk.E))
        
        # Decryption section for Server
        decrypt_frame = ttk.LabelFrame(self.server_frame, text="Manual Decryption")
        decrypt_frame.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky=(tk.W, tk.E))
        
        ttk.Button(decrypt_frame, text="Decrypt Selected Log Entry", command=lambda: self.decrypt_selected_log_entry(self.server_log, self.server_decrypt_output)).pack(anchor=tk.W, padx=10, pady=5)
        
        self.server_decrypt_output = scrolledtext.ScrolledText(decrypt_frame, width=50, height=3)
        self.server_decrypt_output.pack(fill=tk.X, padx=10, pady=5)
        
    def setup_client_tab(self):
        # Client configuration
        ttk.Label(self.client_frame, text="Server Host:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.client_host = ttk.Entry(self.client_frame, width=15)
        self.client_host.insert(0, self.get_local_ip())
        self.client_host.grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)
        
        ttk.Label(self.client_frame, text="Server Port:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        self.client_port = ttk.Entry(self.client_frame, width=5)
        self.client_port.insert(0, "8000")
        self.client_port.grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)
        
        # Connect button
        self.connect_button = ttk.Button(self.client_frame, text="Connect to Server", command=self.connect_to_server)
        self.connect_button.grid(row=2, column=0, padx=10, pady=10, sticky=tk.W)
        
        self.disconnect_button = ttk.Button(self.client_frame, text="Disconnect", command=self.disconnect_from_server, state="disabled")
        self.disconnect_button.grid(row=2, column=1, padx=10, pady=10, sticky=tk.W)
        
        # Message section
        message_frame = ttk.LabelFrame(self.client_frame, text="Send Message")
        message_frame.grid(row=3, column=0, padx=10, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Message to send
        ttk.Label(message_frame, text="Message:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.client_message = scrolledtext.ScrolledText(message_frame, width=40, height=5)
        self.client_message.grid(row=1, column=0, padx=10, pady=5, sticky=(tk.W, tk.E))
        
        # Encrypt before sending checkbox
        self.encrypt_message = tk.BooleanVar()
        # Encrypt options frame
        encrypt_frame = ttk.Frame(message_frame)
        encrypt_frame.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
        
        self.encrypt_checkbox = ttk.Checkbutton(encrypt_frame, text="Encrypt message", variable=self.encrypt_message)
        self.encrypt_checkbox.pack(side=tk.LEFT)
        
        ttk.Button(encrypt_frame, text="Load Key", command=self.load_key).pack(side=tk.LEFT, padx=5)
        
        # Send button
        self.send_button = ttk.Button(message_frame, text="Send Message", command=self.send_message)
        self.send_button.grid(row=3, column=0, padx=10, pady=10, sticky=tk.W)
        
        # File transfer section (next to message_frame)
        file_transfer_frame = ttk.LabelFrame(self.client_frame, text="File Transfer")
        file_transfer_frame.grid(row=3, column=1, padx=10, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.client_file_path_var = tk.StringVar()
        ttk.Entry(file_transfer_frame, textvariable=self.client_file_path_var, width=25).pack(fill=tk.X, padx=5, pady=2)
        
        file_btn_frame = ttk.Frame(file_transfer_frame)
        file_btn_frame.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Button(file_btn_frame, text="Browse File", command=lambda: self.browse_file_for_transfer('client')).pack(side=tk.LEFT, padx=2)
        ttk.Button(file_btn_frame, text="Browse Folder", command=lambda: self.browse_folder_for_transfer('client')).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(file_transfer_frame, text="Send File/Folder", command=self.send_file_to_server).pack(fill=tk.X, padx=5, pady=2)
        
        # Client log
        log_frame = ttk.LabelFrame(self.client_frame, text="Client Log")
        log_frame.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky=(tk.W, tk.E))
        
        self.client_log = scrolledtext.ScrolledText(log_frame, width=50, height=10)
        self.client_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Decryption section for Client
        decrypt_frame = ttk.LabelFrame(self.client_frame, text="Manual Decryption")
        decrypt_frame.grid(row=5, column=0, columnspan=2, padx=10, pady=5, sticky=(tk.W, tk.E))
        
        ttk.Button(decrypt_frame, text="Decrypt Selected Log Entry", command=lambda: self.decrypt_selected_log_entry(self.client_log, self.client_decrypt_output)).pack(anchor=tk.W, padx=10, pady=5)
        
        self.client_decrypt_output = scrolledtext.ScrolledText(decrypt_frame, width=50, height=3)
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
            self.start_server_button.config(state="disabled")
            self.stop_server_button.config(state="normal")
            
            self.update_server_log("Server started successfully.\n")
        except Exception as e:
            self.update_server_log(f"Server error: {str(e)}\n")
            # Re-enable start button on error
            self.root.after(0, lambda: self.start_server_button.config(state="normal"))
            self.root.after(0, lambda: self.stop_server_button.config(state="disabled"))
    
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
            if client_str not in self.clients_listbox.get(0, tk.END):
                self.root.after(0, lambda: self.clients_listbox.insert(tk.END, client_str))
        except Exception as e:
            self.update_server_log(f"Error handling client message: {str(e)}\n")
    
    def handle_client_kicked(self, client_address, reason):
        """Called when a client is kicked"""
        self.update_server_log(f"Client {client_address} has been kicked: {reason}\n")
        
        # Remove from listbox
        client_str = f"{client_address[0]}:{client_address[1]}"
        for i in range(self.clients_listbox.size()):
            if self.clients_listbox.get(i) == client_str:
                self.clients_listbox.delete(i)
                break
    
    def on_client_selected(self, event):
        # Get selected client from listbox
        selection = self.clients_listbox.curselection()
        if selection:
            index = selection[0]
            selected_address = self.clients_listbox.get(index)
            
            # Parse the address (format is "ip:port")
            try:
                ip, port = selected_address.split(':')
                port = int(port)
                self.selected_client = (ip, port)
            except:
                self.selected_client = None
    
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
        self.server_log.see(tk.END)
    
    def stop_server(self):
        if self.server_instance:
            self.update_server_log("Stopping server...\n")
            self.server_instance.close()
            self.server_instance = None
            
            # Clear the clients listbox
            self.clients_listbox.delete(0, tk.END)
        
        # Update UI
        self.start_server_button.config(state="normal")
        self.stop_server_button.config(state="disabled")
        self.update_server_log("Server stopped.\n")
    
    def connect_to_server(self):
        try:
            host = self.client_host.get()
            port = int(self.client_port.get())
            
            self.client_log.insert(tk.END, f"Connecting to server at {host}:{port}...\n")
            self.client_log.see(tk.END)
            
            self.client = Client(host, port)
            
            # Set up callback for incoming messages
            self.client.set_message_callback(self.handle_server_message)
            
            # Set up callback for disconnection
            self.client.set_disconnect_callback(self.handle_disconnection)
            
            # Update UI
            self.connect_button.config(state="disabled")
            self.disconnect_button.config(state="normal")
            
            self.client_log.insert(tk.END, "Connected successfully!\n")
            self.client_log.see(tk.END)
        except Exception as e:
            self.client_log.insert(tk.END, f"Connection error: {str(e)}\n")
            self.client_log.see(tk.END)
    
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
        self.client_log.see(tk.END)
        
        # Update UI
        self.connect_button.config(state="normal")
        self.disconnect_button.config(state="disabled")
        
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
        input_frame = ttk.LabelFrame(self.hashing_frame, text="Input")
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(input_frame, text="Enter text to hash:").pack(anchor=tk.W, padx=5, pady=2)
        self.hash_input_text = scrolledtext.ScrolledText(input_frame, width=60, height=5)
        self.hash_input_text.pack(fill=tk.X, padx=5, pady=5)
        
        # File selection
        file_frame = ttk.Frame(input_frame)
        file_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.hash_file_path_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.hash_file_path_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(file_frame, text="Browse File...", command=self.browse_hash_file).pack(side=tk.LEFT, padx=5)
        
        # Options section
        options_frame = ttk.LabelFrame(self.hashing_frame, text="Options")
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(options_frame, text="Hash Algorithm:").pack(side=tk.LEFT, padx=5, pady=5)
        self.hash_type_combo = ttk.Combobox(options_frame, values=self.hash_types, state="readonly")
        self.hash_type_combo.set("sha256")
        self.hash_type_combo.pack(side=tk.LEFT, padx=5, pady=5)
        self.hash_type_combo.bind("<<ComboboxSelected>>", self.on_hash_type_change)
        
        # Actions
        action_frame = ttk.Frame(self.hashing_frame)
        action_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(action_frame, text="Hash Text", command=self.hash_text).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Hash File", command=self.hash_file).pack(side=tk.LEFT, padx=5)
        
        # Output section
        output_frame = ttk.LabelFrame(self.hashing_frame, text="Output")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.hash_output_text = scrolledtext.ScrolledText(output_frame, width=60, height=5)
        self.hash_output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def setup_cracking_tab(self):
        # Input section
        input_frame = ttk.LabelFrame(self.cracking_frame, text="Input")
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(input_frame, text="Hash to Crack:").pack(anchor=tk.W, padx=5, pady=2)
        self.crack_input_text = ttk.Entry(input_frame, width=60)
        self.crack_input_text.pack(fill=tk.X, padx=5, pady=5)
        
        # Options section
        options_frame = ttk.LabelFrame(self.cracking_frame, text="Options")
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(options_frame, text="Hash Algorithm:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.crack_hash_type_combo = ttk.Combobox(options_frame, values=self.hasher.get_hash_types(), state="readonly")
        self.crack_hash_type_combo.set("sha256")
        self.crack_hash_type_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(options_frame, text="Max Length:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.crack_max_length = ttk.Entry(options_frame, width=5)
        self.crack_max_length.insert(0, "4")
        self.crack_max_length.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(options_frame, text="Charset:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.crack_charset = ttk.Entry(options_frame, width=40)
        self.crack_charset.insert(0, "abcdefghijklmnopqrstuvwxyz0123456789")
        self.crack_charset.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Actions
        action_frame = ttk.Frame(self.cracking_frame)
        action_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(action_frame, text="Estimate Time", command=self.estimate_crack_time).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Start Cracking", command=self.start_cracking).pack(side=tk.LEFT, padx=5)
        
        # Output section
        output_frame = ttk.LabelFrame(self.cracking_frame, text="Output")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.crack_output_text = scrolledtext.ScrolledText(output_frame, width=60, height=10)
        self.crack_output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

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
            
            import threading
            import time
            threading.Thread(target=crack_thread, daemon=True).start()
            
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
            
    def on_hash_type_change(self, event):
        self.current_hash_type = self.hash_type_combo.get()
        
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
    def load_saved_usernames(self):
        """Load saved usernames from file"""
        try:
            usernames_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fc_usernames.json")
            if os.path.exists(usernames_file):
                with open(usernames_file, 'r') as f:
                    return json.load(f)
            return []
        except:
            return []
    
    def save_username(self, username):
        """Save username to file"""
        try:
            if username not in self.fc_saved_usernames:
                self.fc_saved_usernames.append(username)
                usernames_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fc_usernames.json")
                with open(usernames_file, 'w') as f:
                    json.dump(self.fc_saved_usernames, f)
                self.fc_username_combo['values'] = self.fc_saved_usernames
        except Exception as e:
            print(f"Error saving username: {e}")
    
    def fc_create_new_username(self):
        """Create a new username"""
        from tkinter import simpledialog
        username = simpledialog.askstring("New Username", "Enter your new username:")
        
        if username:
            username = username.strip()
            if username:
                self.save_username(username)
                self.fc_username_var.set(username)
                messagebox.showinfo("Success", f"Username '{username}' created and saved!")
    
    def fc_log_message(self, message):
        """Add message to Fast Connect chat log"""
        self.fc_chat_log.config(state="normal")
        self.fc_chat_log.insert(tk.END, message + "\n")
        self.fc_chat_log.see(tk.END)
        self.fc_chat_log.config(state="disabled")
    
    # Fast Connect Tab
    def setup_fast_connect_tab(self):
        """Setup the Fast Connect tab with auto-server and username management"""
        from tkinter import simpledialog
        
        # Initialize fast connect variables
        self.fc_server = None
        self.fc_client = None
        self.fc_my_username = ""
        self.fc_saved_usernames = self.load_saved_usernames()
        self.fc_online_users = {}  # {username: client_address}
        self.fc_current_chat = None  # username or group name
        self.fc_groups = []
        
        # My Username Section
        user_frame = ttk.LabelFrame(self.fast_connect_frame, text="My Username", padding="10")
        user_frame.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky=(tk.W, tk.E))
        
        ttk.Label(user_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.fc_username_var = tk.StringVar()
        self.fc_username_combo = ttk.Combobox(user_frame, textvariable=self.fc_username_var, width=20)
        self.fc_username_combo['values'] = self.fc_saved_usernames
        self.fc_username_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        btn_frame = ttk.Frame(user_frame)
        btn_frame.grid(row=1, column=0, columnspan=2, pady=5)
        
        ttk.Button(btn_frame, text="New Username", command=self.fc_create_new_username).pack(side=tk.LEFT, padx=2)
        self.fc_connect_btn = ttk.Button(btn_frame, text="Connect", command=self.fc_connect)
        self.fc_connect_btn.pack(side=tk.LEFT, padx=2)
        
        self.fc_disconnect_btn = ttk.Button(btn_frame, text="Disconnect", command=self.fc_disconnect, state="disabled")
        self.fc_disconnect_btn.pack(side=tk.LEFT, padx=2)
        
        # Groups
        group_frame = ttk.LabelFrame(self.fast_connect_frame, text="Groups", padding="10")
        group_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky=(tk.W, tk.E))
        
        ttk.Label(group_frame, text="Current Group:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.fc_group_var = tk.StringVar(value="Global Chat")
        self.fc_group_combo = ttk.Combobox(group_frame, textvariable=self.fc_group_var, state="readonly", width=20)
        self.fc_group_combo['values'] = ["Global Chat"]
        self.fc_group_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        self.fc_group_combo.bind('<<ComboboxSelected>>', self.fc_on_group_changed)
        
        group_btn_frame = ttk.Frame(group_frame)
        group_btn_frame.grid(row=1, column=0, columnspan=2, pady=5)
        
        self.fc_create_group_btn = ttk.Button(group_btn_frame, text="Create Group", command=self.fc_create_group, state="disabled")
        self.fc_create_group_btn.pack(side=tk.LEFT, padx=2)
        
        self.fc_join_group_btn = ttk.Button(group_btn_frame, text="Join Group", command=self.fc_join_group, state="disabled")
        self.fc_join_group_btn.pack(side=tk.LEFT, padx=2)
        
        self.fc_leave_group_btn = ttk.Button(group_btn_frame, text="Leave Group", command=self.fc_leave_group, state="disabled")
        self.fc_leave_group_btn.pack(side=tk.LEFT, padx=2)
        
        # Messaging
        msg_frame = ttk.LabelFrame(self.fast_connect_frame, text="Messaging", padding="10")
        msg_frame.grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky=(tk.W, tk.E))
        
        ttk.Label(msg_frame, text="Message:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.fc_message_entry = scrolledtext.ScrolledText(msg_frame, width=40, height=3)
        self.fc_message_entry.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        self.fc_send_btn = ttk.Button(msg_frame, text="Send Message", command=self.fc_send_message, state="disabled")
        self.fc_send_btn.grid(row=2, column=0, columnspan=2, pady=5)
        
        # Chat log
        log_frame = ttk.LabelFrame(self.fast_connect_frame, text="Chat", padding="10")
        log_frame.grid(row=4, column=0, columnspan=2, padx=10, pady=10, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.fc_chat_log = scrolledtext.ScrolledText(log_frame, width=50, height=12, state="disabled")
        self.fc_chat_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure grid weights
        self.fast_connect_frame.columnconfigure(0, weight=1)
        self.fast_connect_frame.rowconfigure(4, weight=1)
    
    def fc_connect(self):
        """Auto-connect: Start server and connect as client"""
        username = self.fc_username_var.get().strip()
        if not username:
            messagebox.showwarning("Warning", "Please select or create a username first.")
            return
        
        try:
            # Start server automatically on port 9000
            self.fc_my_username = username
            host = self.get_local_ip()
            port = 9000
            
            # Start server (starts automatically in __init__)
            from server import Server
            self.fc_server = Server(host, port)
            
            # Give server a moment to start
            import time
            time.sleep(0.5)
            
            # Connect as client to own server
            from client import Client
            self.fc_client = Client(host, port)
            self.fc_client.set_message_callback(self.fc_handle_message)
            self.fc_client.set_disconnect_callback(self.fc_handle_disconnect)
            
            # Announce username
            self.fc_client.send(json.dumps({"type": "announce", "username": self.fc_my_username}))
            
            self.fc_log_message(f"✓ Connected as {self.fc_my_username}")
            self.fc_log_message(f"✓ Server running on {host}:{port}")
            self.fc_log_message(f"✓ Share this address with others to connect!")
            
            # Update UI
            self.fc_username_combo.config(state="disabled")
            self.fc_connect_btn.config(state="disabled")
            self.fc_disconnect_btn.config(state="normal")
            self.fc_send_btn.config(state="normal")
            
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {str(e)}")
            if self.fc_server:
                self.fc_server.close()
                self.fc_server = None
    
    def fc_call_user(self):
        """Call/chat with a specific user"""
        from tkinter import simpledialog
        username = simpledialog.askstring("Call User", "Enter username to call:")
        
        if username:
            username = username.strip()
            if username:
                self.fc_current_chat = username
                self.fc_log_message(f"📞 Calling {username}...")
                # Send call request
                self.fc_client.send(json.dumps({
                    "type": "call_user",
                    "from": self.fc_my_username,
                    "to": username
                }))
    
    def fc_send_message(self):
        """Send message in Fast Connect"""
        message = self.fc_message_entry.get("1.0", tk.END).strip()
        if not message:
            messagebox.showwarning("Warning", "Please enter a message.")
            return
        
        if not self.fc_client:
            messagebox.showwarning("Warning", "Not connected.")
            return
        
        try:
            msg_data = {
                "type": "chat",
                "from": self.fc_my_username,
                "to": self.fc_current_chat,  # None for global, username for direct
                "message": message
            }
            
            self.fc_client.send(json.dumps(msg_data))
            
            if self.fc_current_chat:
                self.fc_log_message(f"[To {self.fc_current_chat}] You: {message}")
            else:
                self.fc_log_message(f"You: {message}")
            
            self.fc_message_entry.delete("1.0", tk.END)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {str(e)}")
    
    def fc_disconnect(self):
        """Disconnect from server"""
        if self.fc_client:
            self.fc_client.close()
            self.fc_client = None
        
        if self.fc_server:
            self.fc_server.close()
            self.fc_server = None
        
        self.fc_log_message("Disconnected from server")
        
        # Reset state
        self.fc_current_chat = None
        self.fc_groups = []
        self.fc_group_combo['values'] = ["Global Chat"]
        self.fc_group_var.set("Global Chat")
        
        # Update UI
        self.fc_username_combo.config(state="normal")
        self.fc_connect_btn.config(state="normal")
        self.fc_disconnect_btn.config(state="disabled")
        self.fc_send_btn.config(state="disabled")
    
    def fc_handle_message(self, message):
        """Handle incoming messages"""
        try:
            msg_data = json.loads(message)
            msg_type = msg_data.get('type', '')
            
            if msg_type == 'chat':
                from_user = msg_data.get('from', 'Unknown')
                msg_text = msg_data.get('message', '')
                to_user = msg_data.get('to')
                
                if to_user == self.fc_my_username:
                    self.root.after(0, lambda: self.fc_log_message(f"[From {from_user}] {msg_text}"))
                elif to_user is None:
                    self.root.after(0, lambda: self.fc_log_message(f"{from_user}: {msg_text}"))
            
            elif msg_type == 'call_user':
                from_user = msg_data.get('from', '')
                self.root.after(0, lambda: self.fc_log_message(f"📞 Incoming call from {from_user}"))
                self.fc_current_chat = from_user
            
        except:
            self.root.after(0, lambda: self.fc_log_message(f"Server: {message}"))
    
    def fc_handle_disconnect(self, reason):
        """Handle disconnection"""
        self.root.after(0, lambda: self.fc_log_message(f"Disconnected: {reason}"))
        self.root.after(0, self.fc_disconnect)
    
    def fc_create_group_chat(self):
        """Create a group chat (stub)"""
        messagebox.showinfo("Info", "Group chat feature coming soon!")
    
    def fc_on_user_selected(self, event):
        """Handle user selection (stub)"""
        pass
    
    def fc_on_group_changed(self, event):
        """Handle group change (stub)"""
        pass
    
    def fc_create_group(self):
        """Create a new group"""
        from tkinter import simpledialog
        group_name = simpledialog.askstring("Create Group", "Enter group name:")
        
        if not group_name:
            return
        
        group_name = group_name.strip()
        
        if not group_name:
            messagebox.showwarning("Warning", "Group name cannot be empty.")
            return
        
        if group_name in self.fc_groups or group_name == "Global Chat":
            messagebox.showwarning("Warning", "Group already exists.")
            return
        
        # Send group creation message
        msg_data = {
            "type": "create_group",
            "group_name": group_name,
            "creator": self.fc_username
        }
        
        self.fc_client.send(json.dumps(msg_data))
        
        # Add to local groups
        self.fc_groups.append(group_name)
        self.fc_group_combo['values'] = ["Global Chat"] + self.fc_groups
        
        # Auto-join
        self.fc_current_group = group_name
        self.fc_group_var.set(group_name)
        
        self.fc_log_message(f"✓ Created and joined group: {group_name}")
        self.fc_leave_group_btn.config(state="normal")
    
    def fc_join_group(self):
        """Join an existing group"""
        from tkinter import simpledialog
        if not self.fc_groups:
            messagebox.showinfo("Info", "No groups available. Create one first!")
            return
        
        group_name = simpledialog.askstring("Join Group", f"Enter group name to join:\n\nAvailable: {', '.join(self.fc_groups)}")
        
        if not group_name:
            return
        
        group_name = group_name.strip()
        
        if group_name not in self.fc_groups:
            messagebox.showwarning("Warning", f"Group '{group_name}' does not exist.")
            return
        
        # Send join message
        msg_data = {
            "type": "join_group",
            "group_name": group_name,
            "username": self.fc_username
        }
        
        self.fc_client.send(json.dumps(msg_data))
        
        self.fc_current_group = group_name
        self.fc_group_var.set(group_name)
        
        self.fc_log_message(f"✓ Joined group: {group_name}")
        self.fc_leave_group_btn.config(state="normal")
    
    def fc_leave_group(self):
        """Leave current group"""
        if not self.fc_current_group:
            messagebox.showinfo("Info", "You are in Global Chat.")
            return
        
        # Send leave message
        msg_data = {
            "type": "leave_group",
            "group_name": self.fc_current_group,
            "username": self.fc_username
        }
        
        self.fc_client.send(json.dumps(msg_data))
        
        self.fc_log_message(f"✓ Left group: {self.fc_current_group}")
        
        self.fc_current_group = None
        self.fc_group_var.set("Global Chat")
        self.fc_leave_group_btn.config(state="disabled")
    
    def fc_on_group_changed(self, event):
        """Handle group selection change"""
        selected = self.fc_group_var.get()
        
        if selected == "Global Chat":
            if self.fc_current_group:
                self.fc_leave_group()
        else:
            if selected != self.fc_current_group:
                self.fc_current_group = selected
                msg_data = {
                    "type": "join_group",
                    "group_name": selected,
                    "username": self.fc_username
                }
                self.fc_client.send(json.dumps(msg_data))
                self.fc_log_message(f"✓ Switched to group: {selected}")
                self.fc_leave_group_btn.config(state="normal")
    
    def fc_send_message(self):
        """Send message in Fast Connect"""
        message = self.fc_message_entry.get("1.0", tk.END).strip()
        if not message:
            messagebox.showwarning("Warning", "Please enter a message.")
            return
        
        if not self.fc_client:
            messagebox.showwarning("Warning", "Not connected to server.")
            return
        
        try:
            msg_data = {
                "type": "chat",
                "username": self.fc_username,
                "message": message,
                "group": self.fc_current_group
            }
            
            self.fc_client.send(json.dumps(msg_data))
            
            if self.fc_current_group:
                self.fc_log_message(f"[{self.fc_current_group}] You: {message}")
            else:
                self.fc_log_message(f"You: {message}")
            
            self.fc_message_entry.delete("1.0", tk.END)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {str(e)}")
    
    def fc_handle_message(self, message):
        """Handle incoming messages"""
        try:
            try:
                msg_data = json.loads(message)
                msg_type = msg_data.get('type', '')
                
                if msg_type == 'chat':
                    username = msg_data.get('username', 'Unknown')
                    msg_text = msg_data.get('message', '')
                    group = msg_data.get('group')
                    
                    if group:
                        self.root.after(0, lambda: self.fc_log_message(f"[{group}] {username}: {msg_text}"))
                    else:
                        self.root.after(0, lambda: self.fc_log_message(f"{username}: {msg_text}"))
                
                elif msg_type == 'group_created':
                    group_name = msg_data.get('group_name', '')
                    creator = msg_data.get('creator', '')
                    if group_name not in self.fc_groups:
                        self.fc_groups.append(group_name)
                        self.root.after(0, lambda: self.fc_update_group_list())
                    self.root.after(0, lambda: self.fc_log_message(f"📢 {creator} created group: {group_name}"))
                
                elif msg_type == 'user_joined':
                    username = msg_data.get('username', '')
                    group_name = msg_data.get('group_name', '')
                    self.root.after(0, lambda: self.fc_log_message(f"👋 {username} joined {group_name}"))
                
                elif msg_type == 'user_left':
                    username = msg_data.get('username', '')
                    group_name = msg_data.get('group_name', '')
                    self.root.after(0, lambda: self.fc_log_message(f"👋 {username} left {group_name}"))
                
                else:
                    self.root.after(0, lambda: self.fc_log_message(f"Server: {message}"))
            except:
                self.root.after(0, lambda: self.fc_log_message(f"Server: {message}"))
        except Exception as e:
            self.root.after(0, lambda: self.fc_log_message(f"Error: {str(e)}"))
    
    def fc_update_group_list(self):
        """Update group combobox"""
        self.fc_group_combo['values'] = ["Global Chat"] + self.fc_groups
    
    def fc_handle_disconnect(self, reason):
        """Handle disconnection"""
        self.root.after(0, lambda: self.fc_log_message(f"Disconnected: {reason}"))
        self.root.after(0, self.fc_disconnect)
    
    def fc_log_message(self, message):
        """Add message to chat log"""
        self.fc_chat_log.config(state="normal")
        self.fc_chat_log.insert(tk.END, message + "\n")
        self.fc_chat_log.see(tk.END)
        self.fc_chat_log.config(state="disabled")




if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()