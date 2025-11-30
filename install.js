// Installation handler for GitHub-based download
document.addEventListener('DOMContentLoaded', () => {
    const downloadBtn = document.querySelector('.download-btn');

    if (downloadBtn) {
        downloadBtn.addEventListener('click', async (e) => {
            e.preventDefault();

            // Show loading state
            const originalText = downloadBtn.innerHTML;
            downloadBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Preparing Download...';
            downloadBtn.style.pointerEvents = 'none';

            try {
                // Create ZIP file with GitHub files + local additions
                await createAndDownloadZip();

                // Show success message
                showNotification('Download started! Check your Downloads folder.', 'success');

                // Reset button after delay
                setTimeout(() => {
                    downloadBtn.innerHTML = originalText;
                    downloadBtn.style.pointerEvents = 'auto';
                }, 2000);

            } catch (error) {
                console.error('Download error:', error);
                showNotification('Download failed. Please try again.', 'error');
                downloadBtn.innerHTML = originalText;
                downloadBtn.style.pointerEvents = 'auto';
            }
        });
    }
});

async function createAndDownloadZip() {
    // Load JSZip library dynamically if not already loaded
    if (typeof JSZip === 'undefined') {
        const script = document.createElement('script');
        script.src = 'https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js';
        document.head.appendChild(script);

        await new Promise((resolve) => {
            script.onload = resolve;
        });
    }

    const zip = new JSZip();

    // GitHub repository base URL (raw content)
    const githubBase = 'https://raw.githubusercontent.com/bdy612/Whaltes/main';

    // Files to download from GitHub repository
    const githubFiles = [
        'Files/client.py',
        'Files/hash.py',
        'Files/index.py',
        'Files/main.py',
        'Files/server.py'
    ];

    // Download files from GitHub
    showNotification('Downloading files from GitHub...', 'info');

    for (const file of githubFiles) {
        try {
            const response = await fetch(`${githubBase}/${file}`);
            if (response.ok) {
                const content = await response.text();
                zip.file(file, content);
            } else {
                console.warn(`Could not fetch ${file} from GitHub`);
                showNotification(`Warning: Could not fetch ${file}`, 'error');
            }
        } catch (error) {
            console.warn(`Error fetching ${file}:`, error);
        }
    }

    // Add locally created files
    showNotification('Creating installation files...', 'info');
    zip.file('runner.py', generateRunnerPy());
    zip.file('Documentation.md', generateDocumentation());
    zip.file('FILE_ENCRYPTION_FEATURES.md', generateFeaturesDoc());
    zip.file('README.md', generateReadme());
    zip.file('install.bat', generateInstallScript());
    zip.file('create_shortcut.vbs', generateShortcutScript());

    // Generate ZIP
    showNotification('Creating installation package...', 'info');
    const blob = await zip.generateAsync({
        type: 'blob',
        compression: 'DEFLATE',
        compressionOptions: { level: 9 }
    });

    // Trigger download
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'Whlates-v2.6-2025.zip';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function generateRunnerPy() {
    return `#!/usr/bin/env python3
"""
Whlates - Secure Encryption Suite
Version 2.6 - 2025 Edition
Runner Script
"""

import tkinter as tk
from Files.index import EncryptionApp

def main():
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
`;
}

function generateDocumentation() {
    return `# Whlates Documentation - Version 2.6 (2025 Edition)

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Features](#features)
4. [Usage Guide](#usage-guide)
5. [Troubleshooting](#troubleshooting)

## Introduction

Whlates is a comprehensive encryption suite that provides:
- Advanced file and text encryption (AES-256, Vigenère, Caesar)
- Secure group chat functionality
- Key management system
- Hashing and password cracking tools
- Professional dark UI theme

## Installation

### Requirements
- Python 3.8 or higher
- Windows OS (for desktop shortcut)

### Quick Install
1. Extract the ZIP file to your desired location
2. Run \`install.bat\` as Administrator
3. The installer will:
   - Check Python installation
   - Install required dependencies (pycryptodome)
   - Create desktop shortcut "Whlates App"
   - Launch the application automatically

### Manual Install
\`\`\`bash
# Install dependencies
pip install pycryptodome

# Run the application
python runner.py
\`\`\`

## Features

### Encryption Tab
- **Text Encryption**: Encrypt/decrypt text using multiple algorithms
- **File Encryption**: Secure any file type (MP3, PDF, images, etc.)
- **Folder Encryption**: Encrypt entire directories
- **Key Management**: Save, edit, and organize encryption keys with names and tags

### Hashing Tab
- Generate hashes: MD5, SHA-1, SHA-256, SHA-512
- Hash text or files
- Verify file integrity

### Cracking Tab
- Brute force password cracking
- Dictionary attacks
- Test password strength

### Server/Client Tabs
- Host encrypted chat server
- Connect as client
- Send encrypted messages
- File transfer support

### Fast Connect Tab
- Quick username-based connection
- Group chat functionality
- Create/join/leave chat rooms
- Real-time messaging

## Usage Guide

### Encrypting a File
1. Go to **Encryption** tab
2. Select encryption method (AES recommended)
3. Click **Browse File**
4. Enter encryption parameters (or click Randomize)
5. Enter **Key Name** and **Tag** in the Tags section
6. Click **Encrypt File/Folder**
7. Click **Save Encryption Key** to save for later use

### Decrypting a File
1. Go to **Encryption** tab
2. Click **Load Encryption Key** to load a saved key
3. Click **Decrypt File/Folder**
4. Select the encrypted file (.enc or .json)
5. File will be decrypted to \`decrypted_files\` folder

### Managing Keys
1. Click **Load Encryption Key**
2. In the key manager window:
   - **Load Key**: Select and load a key
   - **Edit Key**: Change name or tag
   - **Delete Key**: Remove unwanted keys

### Group Chat
1. Go to **Fast Connect** tab
2. Enter your username
3. Enter server host and port
4. Click **Connect**
5. Use **Create Group** to make a new chat room
6. Use **Join Group** to enter existing rooms
7. Type messages and click **Send Message**

## Troubleshooting

### Python Not Found
- Download from https://python.org/downloads/
- During installation, check "Add Python to PATH"

### Import Error: pycryptodome
\`\`\`bash
pip install pycryptodome
\`\`\`

### Desktop Shortcut Not Created
- Run \`create_shortcut.vbs\` manually
- Or run \`install.bat\` as Administrator

### Cannot Decrypt File
- Ensure you have the correct encryption key loaded
- Check that the file is a valid encrypted file (.enc or .json)
- Verify the encryption method matches

### Server Won't Start
- Check if port 8000 is already in use
- Try a different port number
- Ensure firewall allows Python

## Advanced Features

### Custom Randomization
- Set custom ranges for Caesar cipher (1-25)
- Define character sets for Vigenère keys
- Configure password length and complexity for AES

### Key Tags
- Organize keys by project, file type, or purpose
- Use tags like "work", "personal", "mp3", etc.
- Search and filter keys easily

## Security Notes

- **Never share your encryption keys**
- Use strong, random passwords for AES encryption
- Save your keys in a secure location
- The app stores keys in \`encryption_key.json\` - back this up!

## Support

For issues or questions:
- GitHub: https://github.com/bdy612/Whaltes
- Website: https://bdy612.github.io/Whaltes/

---
© 2025 Whlates. Built for security.
`;
}

function generateFeaturesDoc() {
    return `# Complete Encryption Application - Version 2.6 (2025 Release)

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
- ✅ **Upgraded Fast Connect tab** - Now it's more user-friendly and has more features
- ✅ **Upgraded Server tab** - Now it's more user-friendly and has more features
- ✅ **Upgraded Client tab** - Now it's more user-friendly and has more features
- ✅ **Not Showing Keys** - Now it's not showing keys in the application for security reasons

## Application Tabs

### 1. **Encryption Tab**
- Text encryption/decryption
- File & folder encryption
- Support for Caesar, Vigenère, and AES
- **Randomize button** for secure parameters
- **Show/Hide password** for AES
- Save/load encryption keys with names and tags
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

### 6. **Fast Connect Tab**
- Quick username-based connection
- Group chat functionality
- Create and join groups
- Simple messaging interface
- No encryption complexity - just chat!

## Key Features

✅ **All-in-one** - Encryption, hashing, chat in one app
✅ **Secure** - AES encryption, key tracking
✅ **Organized** - Separate folders for encrypted/decrypted
✅ **Flexible** - Multiple encryption methods
✅ **Social** - Group chat and file sharing
✅ **User-friendly** - Intuitive tabs and controls
✅ **Modern UI** - Professional dark theme with vibrant colors

## Getting Started

### **For Encryption:**
1. Open Encryption tab
2. Choose encryption type
3. Click "Randomize" for secure parameters
4. Encrypt your text/files
5. Enter Key Name and Tag
6. Click "Save Encryption Key"

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

---
© 2025 Whlates. Built for security.
`;
}

function generateReadme() {
    return `# Whlates - Secure Encryption Suite v2.6 (2025 Edition)

## Installation Instructions

1. **Extract the ZIP file** to your desired location (e.g., C:\\Program Files\\Whlates)

2. **Install Python 3.8+** if not already installed
   - Download from: https://www.python.org/downloads/
   - Make sure to check "Add Python to PATH" during installation

3. **Run the Installer**
   - Double-click \`install.bat\`
   - The installer will:
     * Check Python installation
     * Install required dependencies (pycryptodome)
     * Create desktop shortcut "Whlates App"
     * Launch the application automatically

4. **Start Using Whlates**
   - The app will launch automatically after installation
   - Or use the "Whlates App" shortcut on your desktop
   - Or run \`python runner.py\` from the installation folder

## Features

- **Advanced Encryption**: AES-256, Vigenère, and Caesar ciphers
- **Key Management**: Save, edit, and organize encryption keys with names and tags
- **Group Chat**: Secure real-time communication
- **File Encryption**: Encrypt any file type (MP3, PDF, images, etc.)
- **Hash & Crack**: Verify integrity and test security
- **Professional Dark UI**: Modern theme with vibrant colors

## Requirements

- Python 3.8 or higher
- pycryptodome library (auto-installed by install.bat)
- Windows OS (for desktop shortcut)

## Quick Start

1. Run \`install.bat\`
2. App launches automatically!
3. Start encrypting files or chatting securely!

## Documentation

- Full documentation: See \`Documentation.md\`
- Features list: See \`FILE_ENCRYPTION_FEATURES.md\`
- GitHub: https://github.com/bdy612/Whaltes
- Website: https://bdy612.github.io/Whaltes/

## Support

For issues or questions, visit:
- GitHub Issues: https://github.com/bdy612/Whaltes/issues
- Website: https://bdy612.github.io/Whaltes/

---
© 2025 Whlates. Built for security.
`;
}

function generateInstallScript() {
    return `@echo off
echo ========================================
echo Whlates v2.6 - 2025 Edition
echo Installation Script
echo ========================================
echo.

REM Get the current directory
set INSTALL_DIR=%~dp0

echo Installing to: %INSTALL_DIR%
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo Python found!
python --version
echo.

REM Install dependencies
echo Installing dependencies...
echo This may take a moment...
pip install pycryptodome
if errorlevel 1 (
    echo WARNING: Failed to install dependencies
    echo You may need to run this as Administrator
    echo Right-click install.bat and select "Run as Administrator"
    pause
    exit /b 1
)
echo.

REM Create desktop shortcut
echo Creating desktop shortcut...
cscript //nologo "%INSTALL_DIR%create_shortcut.vbs"
if errorlevel 1 (
    echo WARNING: Could not create desktop shortcut
    echo You can run the app manually with: python runner.py
) else (
    echo Desktop shortcut "Whlates App" created successfully!
)
echo.

echo ========================================
echo Installation Complete!
echo ========================================
echo.
echo Launching Whlates...
echo.

REM Launch the application
start "" pythonw.exe "%INSTALL_DIR%runner.py"

echo Whlates is now running!
echo You can also launch it from the desktop shortcut.
echo.
pause
`;
}

function generateShortcutScript() {
    return `Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = oWS.SpecialFolders("Desktop") & "\\Whlates App.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)

' Get the directory where this script is located
sScriptPath = WScript.ScriptFullName
sScriptDir = Left(sScriptPath, InStrRev(sScriptPath, "\\"))

oLink.TargetPath = "pythonw.exe"
oLink.Arguments = Chr(34) & sScriptDir & "runner.py" & Chr(34)
oLink.WorkingDirectory = sScriptDir
oLink.Description = "Whlates - Secure Encryption Suite v2.6 (2025 Edition)"
oLink.IconLocation = "C:\\Windows\\System32\\shell32.dll,48"
oLink.Save

WScript.Echo "Desktop shortcut created successfully!"
`;
}

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;

    let icon = 'info-circle';
    if (type === 'success') icon = 'check-circle';
    if (type === 'error') icon = 'exclamation-circle';

    notification.innerHTML = `
        <i class="fas fa-${icon}"></i>
        <span>${message}</span>
    `;

    // Add to page
    document.body.appendChild(notification);

    // Trigger animation
    setTimeout(() => notification.classList.add('show'), 10);

    // Remove after 4 seconds
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 4000);
}

// Add notification styles
const style = document.createElement('style');
style.textContent = `
.notification {
    position: fixed;
    top: 20px;
    right: 20px;
    background: #1e293b;
    color: #f8fafc;
    padding: 1rem 1.5rem;
    border-radius: 8px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.3);
    display: flex;
    align-items: center;
    gap: 0.75rem;
    transform: translateX(400px);
    transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    z-index: 10000;
    border-left: 4px solid #3b82f6;
}

.notification.show {
    transform: translateX(0);
}

.notification-success {
    border-left-color: #10b981;
}

.notification-error {
    border-left-color: #ef4444;
}

.notification-info {
    border-left-color: #3b82f6;
}

.notification i {
    font-size: 1.25rem;
}

.notification-success i {
    color: #10b981;
}

.notification-error i {
    color: #ef4444;
}

.notification-info i {
    color: #3b82f6;
}
`;
document.head.appendChild(style);
