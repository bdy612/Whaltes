// Installation handler for GitHub Pages deployment
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
                // Create ZIP file with GitHub files
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
                showNotification('Download failed. Please try again or visit GitHub directly.', 'error');
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

    // GitHub repository URLs
    const mainRepo = 'https://raw.githubusercontent.com/bdy612/Whaltes/main';
    const websiteRepo = 'https://raw.githubusercontent.com/bdy612/Whaltes/gh-pages';

    // Files to download and combine into Super_Main.py
    const pythonFiles = [
        'Super_Main.py',
        'Central_Server.py'
    ];

    // Files to download from website repository (documentation)
    const websiteRepoFiles = [
        'Documentation.md',
        'FILE_ENCRYPTION_FEATURES.md',
        'README.md'
    ];

    showNotification('Downloading files from GitHub...', 'info');

    // Download and combine Python files into Super_Main.py
    let superMainContent = `"""
Whlates - Secure Encryption Suite
Version 2.6 - 2025 Edition
Super Main File - All modules combined
"""

`;

    for (const file of pythonFiles) {
        try {
            const response = await fetch(`${mainRepo}/${file}`);
            if (response.ok) {
                const content = await response.text();
                const fileName = file.split('/').pop();
                superMainContent += `\n# ==================== ${fileName} ====================\n\n`;
                superMainContent += content + '\n';
            } else {
                console.warn(`Could not fetch ${file} from main repo`);
            }
        } catch (error) {
            console.warn(`Error fetching ${file}:`, error);
        }
    }

    // Add Super_Main.py to ZIP
    zip.file('Super_Main.py', superMainContent);

    // Download documentation files from website repository
    for (const file of websiteRepoFiles) {
        try {
            const response = await fetch(`${websiteRepo}/${file}`);
            if (response.ok) {
                const content = await response.text();
                zip.file(file, content);
            } else {
                console.warn(`Could not fetch ${file} from website repo`);
                // If not found in website repo, try main repo
                try {
                    const fallbackResponse = await fetch(`${mainRepo}/${file}`);
                    if (fallbackResponse.ok) {
                        const content = await fallbackResponse.text();
                        zip.file(file, content);
                    }
                } catch (e) {
                    console.warn(`Fallback failed for ${file}`);
                }
            }
        } catch (error) {
            console.warn(`Error fetching ${file}:`, error);
        }
    }

    // Add locally generated files
    zip.file('install.bat', generateInstallScript());
    zip.file('run.py', generateRunScript())
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
    a.download = 'Whlates-v2.7-Alpha-2025.zip';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function generateRunScript(){
    return `import os
if __name__ == '__main__':
  os.system('python Central_Server.py')
  os.system('python Super_Main.py')`
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
    echo.
    echo Please install Python 3.8+ from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    echo.
    pause
    exit /b 1
)

echo Python found!
python --version
echo.

REM Install dependencies
echo Installing dependencies...
echo This may take a moment...
echo.
pip install pycryptodome
if errorlevel 1 (
    echo.
    echo WARNING: Failed to install dependencies
    echo You may need to run this as Administrator
    echo Right-click install.bat and select "Run as Administrator"
    echo.
    pause
) else (
    echo.
    echo Dependencies installed successfully!
    echo.
)

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
echo You can now run Whlates from:
echo   1. Desktop shortcut "Whlates App"
echo   2. Command: python "%INSTALL_DIR%runner.py"
echo.
echo For help and documentation:
echo   - See Documentation.md
echo   - See FILE_ENCRYPTION_FEATURES.md
echo   - Visit https://bdy612.github.io/Whaltes/
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
oLink.Arguments = Chr(34) & sScriptDir & "Run.py" & Chr(34)
oLink.WorkingDirectory = sScriptDir
oLink.Description = "Whlates - Secure Encryption Suite v2.7 Alpha (2025 Edition)"
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





