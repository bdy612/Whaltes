// Admin Panel JavaScript
let adminPointsData = [];

// Admin password (in production, this should be handled server-side)
const ADMIN_PASSWORD = "whlates2025admin";

// Load points data
async function adminLoadData() {
    try {
        const response = await fetch('points.json');
        adminPointsData = await response.json();
        refreshUserTable();
    } catch (error) {
        console.error('Error loading data:', error);
        showNotification('Error loading data', 'error');
    }
}

// Refresh the user table
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

// Update statistics
function updateStats() {
    const totalUsers = adminPointsData.length;
    const totalPoints = adminPointsData.reduce((sum, user) => sum + user.Points, 0);
    const proUsers = adminPointsData.filter(u => u.Points >= 1000).length;

    document.getElementById('totalUsers').textContent = totalUsers;
    document.getElementById('totalPoints').textContent = totalPoints.toLocaleString();
    document.getElementById('proUsers').textContent = proUsers;
}

// Add new user
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

// Edit user
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

// Delete user
function deleteUser(index) {
    const user = adminPointsData[index];
    if (confirm(`Delete user ${user.ID}?`)) {
        adminPointsData.splice(index, 1);
        refreshUserTable();
        downloadJSON();
        showNotification('User deleted successfully', 'success');
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

// Download updated JSON
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
