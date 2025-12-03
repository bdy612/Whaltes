// Admin Panel JavaScript
let adminPointsData = [];
let adminAccountsData = [];

// Admin password (in production, this should be handled server-side)
const ADMIN_PASSWORD = "Boody@612#Ahmed_142";

// Load points data
async function adminLoadData() {
    try {
        const response = await fetch('points.json');
        adminPointsData = await response.json();
        refreshUserTable();
    } catch (error) {
        console.error('Error loading data:', error);
        showNotification('Error loading points data', 'error');
    }
}

// Load accounts data
async function adminLoadAccounts() {
    try {
        const response = await fetch('accounts.json');
        adminAccountsData = await response.json();
        refreshAccountsTable();
    } catch (error) {
        console.error('Error loading accounts:', error);
        showNotification('Error loading accounts data', 'error');
    }
}

// Refresh the points user table
function refreshUserTable() {
    const tbody = document.getElementById('userTableBody');
    tbody.innerHTML = '';

    adminPointsData.forEach((user, index) => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${user.ID}</td>
            <td>${user.Points.toLocaleString()}</td>
            <td>
                <button onclick="editUser(${index})" class="btn-edit">Edit</button>
                <button onclick="deleteUser(${index})" class="btn-delete">Delete</button>
            </td>
        `;
        tbody.appendChild(row);
    });

    updateStats();
}

// Refresh the accounts table
function refreshAccountsTable() {
    const tbody = document.getElementById('accountsTableBody');
    if (!tbody) return;

    tbody.innerHTML = '';

    adminAccountsData.forEach((account, index) => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${account.username}</td>
            <td>${account.email}</td>
            <td>${account.points.toLocaleString()}</td>
            <td>
                <button onclick="editAccount(${index})" class="btn-edit">Edit</button>
                <button onclick="deleteAccount(${index})" class="btn-delete">Delete</button>
            </td>
        `;
        tbody.appendChild(row);
    });

    updateAccountStats();
}

// Update statistics
function updateStats() {
    const totalUsers = adminPointsData.length;
    const totalPoints = adminPointsData.reduce((sum, user) => sum + user.Points, 0);
    const proUsers = adminPointsData.filter(u => u.Points >= 1000).length;

    document.getElementById('totalUsers').textContent = totalUsers;
    document.getElementById('totalPoints').textContent = totalPoints.toLocaleString();
    document.getElementById('proUsers').textContent = proUsers;
}

// Update account statistics
function updateAccountStats() {
    const totalAccounts = adminAccountsData.length;
    const totalAccountPoints = adminAccountsData.reduce((sum, acc) => sum + acc.points, 0);
    const proAccounts = adminAccountsData.filter(a => a.points >= 1000).length;

    if (document.getElementById('totalAccounts')) {
        document.getElementById('totalAccounts').textContent = totalAccounts;
        document.getElementById('totalAccountPoints').textContent = totalAccountPoints.toLocaleString();
        document.getElementById('proAccounts').textContent = proAccounts;
    }
}

// Add new user (Points ID system)
function addNewUser() {
    const id = document.getElementById('newUserID').value.trim();
    const points = parseInt(document.getElementById('newUserPoints').value) || 0;

    if (!id) {
        showNotification('Please enter a valid ID', 'error');
        return;
    }

    // Check if user already exists
    if (adminPointsData.find(u => u.ID === id)) {
        showNotification('User ID already exists', 'error');
        return;
    }

    adminPointsData.push({ ID: id, Points: points });
    refreshUserTable();
    downloadJSON();

    document.getElementById('newUserID').value = '';
    document.getElementById('newUserPoints').value = '0';

    showNotification('User added successfully', 'success');
}

// Add new account
function addNewAccount() {
    const username = document.getElementById('newAccountUsername').value.trim();
    const email = document.getElementById('newAccountEmail').value.trim();
    const password = document.getElementById('newAccountPassword').value;
    const points = parseInt(document.getElementById('newAccountPoints').value) || 0;

    if (!username || !email || !password) {
        showNotification('Please fill all fields', 'error');
        return;
    }

    // Check if username exists
    if (adminAccountsData.find(a => a.username === username)) {
        showNotification('Username already exists', 'error');
        return;
    }

    adminAccountsData.push({
        username: username,
        password: password,
        email: email,
        points: points,
        createdAt: new Date().toISOString()
    });

    refreshAccountsTable();
    downloadAccountsJSON();

    document.getElementById('newAccountUsername').value = '';
    document.getElementById('newAccountEmail').value = '';
    document.getElementById('newAccountPassword').value = '';
    document.getElementById('newAccountPoints').value = '0';

    showNotification('Account added successfully', 'success');
}

// Edit user (Points ID)
function editUser(index) {
    const user = adminPointsData[index];
    const newPoints = prompt(`Edit points for ID ${user.ID}:`, user.Points);

    if (newPoints !== null) {
        const points = parseInt(newPoints);
        if (!isNaN(points) && points >= 0) {
            adminPointsData[index].Points = points;
            refreshUserTable();
            downloadJSON();
            showNotification('User updated successfully', 'success');
        } else {
            showNotification('Invalid points value', 'error');
        }
    }
}

// Edit account
function editAccount(index) {
    const account = adminAccountsData[index];
    const newPoints = prompt(`Edit points for ${account.username}:`, account.points);

    if (newPoints !== null) {
        const points = parseInt(newPoints);
        if (!isNaN(points) && points >= 0) {
            adminAccountsData[index].points = points;
            refreshAccountsTable();
            downloadAccountsJSON();
            showNotification('Account updated successfully', 'success');
        } else {
            showNotification('Invalid points value', 'error');
        }
    }
}

// Delete user (Points ID)
function deleteUser(index) {
    const user = adminPointsData[index];
    if (confirm(`Delete user ${user.ID}?`)) {
        adminPointsData.splice(index, 1);
        refreshUserTable();
        downloadJSON();
        showNotification('User deleted successfully', 'success');
    }
}

// Delete account
function deleteAccount(index) {
    const account = adminAccountsData[index];
    if (confirm(`Delete account ${account.username}?`)) {
        adminAccountsData.splice(index, 1);
        refreshAccountsTable();
        downloadAccountsJSON();
        showNotification('Account deleted successfully', 'success');
    }
}

// Add points to user
function modifyPoints(action) {
    const id = document.getElementById('modifyUserID').value.trim();
    const points = parseInt(document.getElementById('modifyPoints').value) || 0;

    if (!id) {
        showNotification('Please enter a user ID', 'error');
        return;
    }

    const user = adminPointsData.find(u => u.ID === id);
    if (!user) {
        showNotification('User not found', 'error');
        return;
    }

    if (action === 'add') {
        user.Points += points;
    } else if (action === 'deduct') {
        user.Points = Math.max(0, user.Points - points);
    } else if (action === 'set') {
        user.Points = points;
    }

    refreshUserTable();
    downloadJSON();

    document.getElementById('modifyUserID').value = '';
    document.getElementById('modifyPoints').value = '0';

    showNotification(`Points ${action}ed successfully`, 'success');
}

// Download updated points JSON
function downloadJSON() {
    const dataStr = JSON.stringify(adminPointsData, null, 4);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'points.json';
    link.click();
    URL.revokeObjectURL(url);
}

// Download updated accounts JSON
function downloadAccountsJSON() {
    const dataStr = JSON.stringify(adminAccountsData, null, 4);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'accounts.json';
    link.click();
    URL.revokeObjectURL(url);
}

// Test points checker
async function testPointsChecker() {
    const testID = document.getElementById('testID').value.trim();
    const resultDiv = document.getElementById('testResult');

    if (!testID) {
        resultDiv.innerHTML = '<p style="color: #ef4444;">Please enter an ID to test</p>';
        return;
    }

    const user = adminPointsData.find(u => u.ID === testID);

    if (user) {
        const isPro = user.Points >= 1000;
        resultDiv.innerHTML = `
            <div style="padding: 1rem; background: ${isPro ? 'rgba(16, 185, 129, 0.1)' : 'rgba(59, 130, 246, 0.1)'}; border-radius: 8px; border: 1px solid ${isPro ? 'rgba(16, 185, 129, 0.3)' : 'rgba(59, 130, 246, 0.3)'};">
                <h4 style="margin: 0 0 0.5rem 0;">ID: ${user.ID}</h4>
                <p style="font-size: 1.5rem; font-weight: bold; margin: 0.5rem 0;">${user.Points.toLocaleString()} Points</p>
                <p style="color: ${isPro ? '#10b981' : '#6b7280'}; margin: 0;">
                    ${isPro ? '✅ Eligible for v2.7 Pro' : '❌ Not enough points for v2.7 Pro'}
                </p>
            </div>
        `;
    } else {
        resultDiv.innerHTML = '<p style="color: #ef4444;">❌ User ID not found</p>';
    }
}

// Show notification
function showNotification(message, type) {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 1rem 1.5rem;
        background: ${type === 'success' ? '#10b981' : '#ef4444'};
        color: white;
        border-radius: 8px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        z-index: 10000;
        animation: slideIn 0.3s ease;
    `;

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Initialize admin panel
function initAdmin() {
    adminLoadData();
    adminLoadAccounts();
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(400px); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(400px); opacity: 0; }
    }
`;
document.head.appendChild(style);
