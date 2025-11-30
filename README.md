# Complete Encryption Application - Version 2.6 (2025 Release)

## Overview
The encryption application is a comprehensive security tool with file encryption, hashing, password cracking, server/client communication, and fast group chat - all in one application.

## Versions

### Version 2.6 - 2025 Edition
- ✅ **Professional Dark UI** - Modern dark theme with vibrant colors and better fonts
- ✅ **Key Management** - Save keys with names and tags
- ✅ **Key Editor** - Edit key names and tags
- ✅ **Key Deletion** - Remove unused keys
- ✅ **Enhanced Decryption** - Decrypt any file type using loaded keys
- ✅ **Custom Randomization** - Set ranges and character sets for random generation

### Version 2.5
- ✅ **Auto-server** - Server starts automatically when application is opened
- ✅ **Auto-client** - Client connects to server automatically when application is opened
- ✅ **Auto-save** - Saved usernames are loaded automatically when application is opened
- ✅ **Upgarded Fast Connect tab** - Now it's more user-friendly and has more features
- ✅ **Upgarded Server tab** - Now it's more user-friendly and has more features
- ✅ **Upgarded Client tab** - Now it's more user-friendly and has more features
- ✅ **Not Showing Keys** - Now it's not showing keys in the application for security reasons

### Version 2.4
- ✅ **Integrated Fast Connect tab** into main application
- ✅ **Group chat functionality**
- ✅ **Username-based quick connection**
- ✅ **Create/join/leave groups**
- ✅ **Group message tagging**

### Version 2.3
- ✅ **Randomize parameters button**
- ✅ **Show/Hide password for AES**
- ✅ **Password masking by default**

### Version 2.2
- ✅ **Encrypted and decrypted files** with key tracking
- ✅ **key.json for each decrypted file/folder**

### Version 2.1
- ✅ **EaHaSaR** (Encrypt and Hash and Save and Receive)
- ✅ **File and folder encryption/decryption**

### Version 2.0
- ✅ **Hashing functionality added**

## Application Tabs

### 1. **Encryption Tab**
- Text encryption/decryption
- File & folder encryption
- Support for Caesar, Vigenère, and AES
- **Randomize button** for secure parameters
- **Show/Hide password** for AES
- Save/load encryption keys
- Organized encrypted_files and encrypted_folders

### 2. **Hashing Tab**
- Hash text or files
- Support for MD5, SHA-1, SHA-256, SHA-512
- Display hash results

### 3. **Cracking Tab**
- Crack encrypted messages
- Brute force and dictionary attacks
- Progress tracking

### 4. **Server Tab**
- Start/stop server
- Manage connected clients
- Send messages to clients
- Send encrypted files/folders
- Broadcast to all clients

### 5. **Client Tab**
- Connect to server
- Send messages
- Send encrypted files/folders
- Receive and decrypt files

### 6. **Fast Connect Tab** ⭐ NEW!
- Quick username-based connection
- Group chat functionality
- Create and join groups
- Simple messaging interface
- No encryption complexity - just chat!

## Fast Connect Tab Features

### **Quick Setup**
1. Enter username
2. Enter server host/port
3. Click Connect
4. Start chatting!

### **Group Management**
- **Global Chat** - Default room for everyone
- **Create Group** - Make private chat rooms
- **Join Group** - Enter existing groups
- **Leave Group** - Return to Global Chat
- **Dropdown selector** - Quick group switching

### **Messaging**
- Send messages to current group
- Messages tagged with group name
- Visual indicators (📢 ✓ 👋)
- Real-time notifications

### **Interface**
```
Fast Connect Tab:
├── User Information
│   └── Username: [Enter name]
├── Connection
│   ├── Server Host: [IP]
│   ├── Server Port: [8000]
│   └── [Connect] [Disconnect]
├── Groups
│   ├── Current Group: [Dropdown]
│   └── [Create] [Join] [Leave]
├── Messaging
│   ├── Message: [Text area]
│   └── [Send Message]
└── Chat
    └── [Chat log with messages]
```

## Version History

### Version 2.6 - 2025 Edition (Current)
- ✅ **Professional Dark UI** - Modern theme with vibrant colors
- ✅ **Key Management** - Save/Edit/Delete keys
- ✅ **Enhanced Decryption** - Support for all file types
- ✅ **Custom Randomization** - Configurable random parameters

### Version 2.5
- ✅ **Auto-start** - Server/Client/Usernames load automatically
- ✅ **UI Upgrades** - Improved tabs and security

### Version 2.4
- ✅ **Integrated Fast Connect tab** into main application
- ✅ Group chat functionality
- ✅ Username-based quick connection
- ✅ Create/join/leave groups
- ✅ Group message tagging

### Version 2.3
- ✅ Randomize parameters button
- ✅ Show/Hide password for AES
- ✅ Password masking by default

### Version 2.2
- ✅ Encrypted and decrypted files with key tracking
- ✅ key.json for each decrypted file/folder

### Version 2.1
- ✅ EaHaSaR (Encrypt and Hash and Save and Receive)
- ✅ File and folder encryption/decryption

### Version 2.0
- ✅ Hashing functionality added

## Directory Structure

```
eencryption/
├── encrypted_files/       # Encrypted files (.enc)
├── encrypted_folders/     # Encrypted folders (.zip)
├── decrypted_files/       # Decrypted files (in folders with key.json)
│   ├── filename/
│   │   ├── filename.ext
│   │   └── key.json
├── decrypted_folders/     # Decrypted folders (with key.json)
│   ├── foldername/
│   │   ├── files...
│   │   └── key.json
└── temp_decrypt/          # Temporary (auto-cleaned)
```

## Use Cases

### **Scenario 1: Secure File Sharing**
1. Go to Encryption tab
2. Select file/folder
3. Encrypt with AES
4. Go to Server tab
5. Send to client
6. Client receives and decrypts automatically

### **Scenario 2: Team Chat**
1. Go to Fast Connect tab
2. Enter username
3. Connect to server
4. Create group "Project Team"
5. Team members join group
6. Collaborate in real-time

### **Scenario 3: Password Cracking**
1. Go to Cracking tab
2. Enter encrypted text
3. Choose attack method
4. Start cracking
5. View results

## Key Features

✅ **All-in-one** - Encryption, hashing, chat in one app
✅ **Secure** - AES encryption, key tracking
✅ **Organized** - Separate folders for encrypted/decrypted
✅ **Flexible** - Multiple encryption methods
✅ **Social** - Group chat and file sharing
✅ **User-friendly** - Intuitive tabs and controls

## Getting Started

### **For Encryption:**
1. Open Encryption tab
2. Choose encryption type
3. Click "Randomize" for secure parameters
4. Encrypt your text/files

### **For Chat:**
1. Open Server tab → Start server
2. Open Fast Connect tab → Connect
3. Create or join groups
4. Start chatting!

### **For File Sharing:**
1. Encrypt files in Encryption tab
2. Send via Server/Client tabs
3. Receiver gets decrypted files automatically

Perfect for secure communication and file sharing!

