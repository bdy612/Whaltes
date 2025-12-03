// Authentication System JavaScript
let accountsData = [];
let currentUser = null;

// Load accounts data
async function loadAccounts() {
    try {
        const response = await fetch('accounts.json');
        accountsData = await response.json();
        return accountsData;
    } catch (error) {
        console.error('Error loading accounts:', error);
        return [];
    }
}

// Check if user is logged in
function checkAuth() {
    const user = localStorage.getItem('currentUser');
    if (user) {
        currentUser = JSON.parse(user);
        return true;
    }
    return false;
}

// Login function
async function login(username, password) {
    await loadAccounts();

    const user = accountsData.find(u => u.username === username && u.password === password);

    if (user) {
        currentUser = user;
        localStorage.setItem('currentUser', JSON.stringify(user));
        return { success: true, user: user };
    }

    return { success: false, message: 'Invalid username or password' };
}

// Sign up function
async function signup(username, password, email, points = 0) {
    await loadAccounts();

    // Check if username already exists
    if (accountsData.find(u => u.username === username)) {
        return { success: false, message: 'Username already exists' };
    }

    // Check if email already exists
    if (accountsData.find(u => u.email === email)) {
        return { success: false, message: 'Email already registered' };
    }

    // Create new user
    const newUser = {
        username: username,
        password: password,
        email: email,
        points: parseInt(points) || 0,
        createdAt: new Date().toISOString()
    };

    accountsData.push(newUser);

    // In production, this would save to server
    // For now, we'll store in localStorage and download JSON
    currentUser = newUser;
    localStorage.setItem('currentUser', JSON.stringify(newUser));

    return { success: true, user: newUser };
}

// Logout function
function logout() {
    currentUser = null;
    localStorage.removeItem('currentUser');
    window.location.href = 'login.html';
}

// Get current user
function getCurrentUser() {
    if (!currentUser) {
        const user = localStorage.getItem('currentUser');
        if (user) {
            currentUser = JSON.parse(user);
        }
    }
    return currentUser;
}

// Update user points
async function updateUserPoints(newPoints) {
    if (!currentUser) return { success: false, message: 'Not logged in' };

    currentUser.points = parseInt(newPoints) || 0;
    localStorage.setItem('currentUser', JSON.stringify(currentUser));

    // Update in accounts data
    const userIndex = accountsData.findIndex(u => u.username === currentUser.username);
    if (userIndex !== -1) {
        accountsData[userIndex].points = currentUser.points;
    }

    return { success: true };
}

// Get user's points
async function getUserPoints() {
    if (!currentUser) {
        return null;
    }

    return currentUser.points || 0;
}

// Save accounts data (for admin)
function saveAccounts() {
    return JSON.stringify(accountsData, null, 4);
}

// Validate email format
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

// Validate password strength
function validatePassword(password) {
    return password.length >= 6;
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        loadAccounts,
        checkAuth,
        login,
        signup,
        logout,
        getCurrentUser,
        updateUserPoints,
        getUserPoints,
        saveAccounts,
        validateEmail,
        validatePassword
    };
}
