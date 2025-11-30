// Installation handler
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
                // Create ZIP file with required files
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
    // Load JSZip library dynamically
    if (typeof JSZip === 'undefined') {
        const script = document.createElement('script');
        script.src = 'https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js';
        document.head.appendChild(script);

        await new Promise((resolve) => {
            script.onload = resolve;
        });
    }

    const zip = new JSZip();

    // File structure to include
    const files = {
        'runner.py': await fetchFileContent('../runner.py'),
        'Files/client.py': await fetchFileContent('../Files/client.py'),
        'Files/hash.py': await fetchFileContent('../Files/hash.py'),
        'Files/index.py': await fetchFileContent('../Files/index.py'),
        'Files/main.py': await fetchFileContent('../Files/main.py'),
        'Files/server.py': await fetchFileContent('../Files/server.py'),
        'Documentation.md': await fetchFileContent('../Documentation.md'),
        'FILE_ENCRYPTION_FEATURES.md': await fetchFileContent('../FILE_ENCRYPTION_FEATURES.md'),
        'README.md': generateReadme(),
        'install.bat': generateInstallScript(),
        'create_shortcut.vbs': generateShortcutScript()
    };

    // Add all files to ZIP
    for (const [path, content] of Object.entries(files)) {
        zip.file(path, content);
    }

    // Generate ZIP
    const blob = await zip.generateAsync({ type: 'blob' });

    // Trigger download
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'Whlates-v2.6.zip';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

async function fetchFileContent(path) {
    try {
        const response = await fetch(path);
        if (!response.ok) {
            // If file doesn't exist, return placeholder
            return `# File: ${path}\n# This file should be included in the installation\n`;
        }
        return await response.text();
    } catch (error) {
        console.warn(`Could not fetch ${path}:`, error);
        return `# File: ${path}\n# This file should be included in the installation\n`;
    }
}

function generateReadme() {
    return `# Whlates - Secure Encryption Suite v2.6

## Installation Instructions

1. **Extract the ZIP file** to your desired location (e.g., C:\\Program Files\\Whlates)

2. **Install Python 3.8+** if not already installed
   - Download from: https://www.python.org/downloads/
   - Make sure to check "Add Python to PATH" during installation

3. **Install Required Dependencies**
   - Open Command Prompt in the extracted folder
   - Run: \`pip install pycryptodome\`

4. **Create Desktop Shortcut**
   - Double-click \`install.bat\` to automatically create a desktop shortcut
   - Or manually run \`create_shortcut.vbs\`

5. **Run the Application**
   - Double-click the "Whlates App" shortcut on your desktop
   - Or run \`python runner.py\` from the installation folder

## Features

- **Advanced Encryption**: AES-256, Vigenère, and Caesar ciphers
- **Key Management**: Save, edit, and organize encryption keys
- **Group Chat**: Secure real-time communication
- **File Encryption**: Encrypt any file type
- **Hash & Crack**: Verify integrity and test security

## Requirements

- Python 3.8 or higher
- pycryptodome library
- Windows OS (for desktop shortcut)

## Support

For issues or questions, refer to the Documentation.md file.

---
© 2025 Whlates. Built for security.
`;
}

function generateInstallScript() {
    return `@echo off
echo ========================================
echo Whlates Installation Script
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
    pause
    exit /b 1
)

echo Python found!
echo.

REM Install dependencies
echo Installing dependencies...
pip install pycryptodome
if errorlevel 1 (
    echo WARNING: Failed to install dependencies
    echo You may need to run this as Administrator
)
echo.

REM Create desktop shortcut
echo Creating desktop shortcut...
cscript //nologo "%INSTALL_DIR%create_shortcut.vbs"
if errorlevel 1 (
    echo WARNING: Could not create desktop shortcut
) else (
    echo Desktop shortcut created successfully!
)
echo.

echo ========================================
echo Installation Complete!
echo ========================================
echo.
echo You can now run Whlates from:
echo 1. Desktop shortcut "Whlates App"
echo 2. Command: python "%INSTALL_DIR%runner.py"
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
oLink.Description = "Whlates - Secure Encryption Suite"
oLink.IconLocation = "C:\\Windows\\System32\\shell32.dll,48"
oLink.Save

WScript.Echo "Desktop shortcut created successfully!"
`;
}

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i>
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

.notification i {
    font-size: 1.25rem;
}

.notification-success i {
    color: #10b981;
}

.notification-error i {
    color: #ef4444;
}
`;
document.head.appendChild(style);
