# New Features - Version 2.3

## Overview
Added parameter randomization and a simplified fast connection client for quick messaging.

## New Features

### 1. **Randomize Parameters Button**

Each encryption type now has a "Randomize" button to generate secure random parameters:

#### **Caesar Cipher**
- Randomize button generates random shift value (1-25)
- Shows the generated value in a popup

#### **Vigenère Cipher**
- Randomize button generates random key (8-16 characters)
- Uses uppercase letters
- Shows the generated key in a popup

#### **AES Encryption**
- Randomize button generates strong 16-character password
- Uses letters, digits, and special characters
- **Shows password in popup - SAVE IT!**
- Password field now masked with `*` by default
- **Show/Hide button** to toggle password visibility

### 2. **Fast Connection Client**

A simplified client application (`fast_client.py`) for quick connections:

#### **Features:**
- ✅ Simple username-based connection
- ✅ Clean chat interface
- ✅ Auto-formatted messages with usernames
- ✅ Connection status indicators
- ✅ Minimal UI - just the essentials

#### **How to Use:**
1. Run `python fast_client.py`
2. Enter your username
3. Enter server host and port
4. Click "Connect"
5. Start chatting!

#### **Interface:**
```
┌─────────────────────────────────┐
│ User Information                │
│ Username: [John]                │
├─────────────────────────────────┤
│ Connection                      │
│ Server Host: [192.168.1.100]    │
│ Server Port: [8000]             │
│ [Connect] [Disconnect]          │
├─────────────────────────────────┤
│ Messaging                       │
│ Message: [Type here...]         │
│ [Send Message]                  │
├─────────────────────────────────┤
│ Chat                            │
│ Connected as John               │
│ You: Hello!                     │
│ Alice: Hi John!                 │
│ Server: Message received        │
└─────────────────────────────────┘
```

## Usage Examples

### Randomize Encryption Parameters

**Caesar:**
1. Select "Caesar+Substitution Cipher"
2. Click "Randomize"
3. Popup shows: "Caesar shift set to: 17"
4. Use for encryption

**AES:**
1. Select "AES Encryption"
2. Click "Randomize"
3. Popup shows: "AES password set to: aB3$xY9#mN2@pQ5!"
4. **IMPORTANT:** Copy and save this password!
5. Click "Show/Hide" to view password in field
6. Use for encryption

### Fast Client Connection

**Scenario: Quick team chat**

**User 1 (Server):**
1. Run main app (`python index.py`)
2. Go to Server tab
3. Click "Start Server"
4. Share IP address with team

**User 2 (Fast Client):**
1. Run fast client (`python fast_client.py`)
2. Username: "Alice"
3. Host: [server IP]
4. Port: 8000
5. Click "Connect"
6. Type message: "Hey team!"
7. Click "Send Message"

**User 3 (Fast Client):**
1. Run another fast client
2. Username: "Bob"
3. Connect to same server
4. See Alice's messages
5. Reply in chat

## Benefits

### Randomize Parameters:
✅ **Security** - Truly random, unpredictable parameters
✅ **Convenience** - No need to think of secure values
✅ **Strength** - Meets security best practices
✅ **Quick** - One click to generate

### Fast Client:
✅ **Simple** - No complex features, just chat
✅ **Fast** - Quick to launch and connect
✅ **Lightweight** - Minimal resource usage
✅ **User-friendly** - Easy for non-technical users
✅ **Multiple instances** - Run many clients easily

## Technical Details

### Randomization Implementation

**Caesar:**
```python
random_shift = random.randint(1, 25)
```

**Vigenère:**
```python
length = random.randint(8, 16)
random_key = ''.join(random.choices(string.ascii_uppercase, k=length))
```

**AES:**
```python
length = 16
characters = string.ascii_letters + string.digits + string.punctuation
random_password = ''.join(random.choices(characters, k=length))
```

### Fast Client Message Format

```json
{
  "type": "chat",
  "username": "Alice",
  "message": "Hello everyone!"
}
```

## Security Notes

⚠️ **IMPORTANT:** When using "Randomize" for AES:
- The password is shown ONCE in the popup
- Make sure to save it immediately
- You won't be able to decrypt without it
- Use "Show/Hide" button to verify password in field

## Version History

### Version 2.3 (Current)
- ✅ Added Randomize button for all encryption types
- ✅ Added Show/Hide password button for AES
- ✅ Created Fast Connection Client (`fast_client.py`)
- ✅ Password field now masked by default

### Version 2.2
- Added encrypted and decrypted files and folders with key tracking

### Version 2.1
- EaHaSaR (Encrypt and Hash and Save and Receive) Files and Folders

### Version 2.0
- Hashing added

## Files

- `index.py` - Main application with all features
- `fast_client.py` - Simple fast connection client
- `main.py` - Encryption core
- `server.py` - Server implementation
- `client.py` - Client implementation
- `hash.py` - Hashing functionality

Perfect for both secure file encryption and quick team communication!
