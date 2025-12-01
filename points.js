// Points System JavaScript
let pointsData = [];

// Load points data from JSON
async function loadPointsData() {
    try {
        const response = await fetch('points.json');
        pointsData = await response.json();
        return pointsData;
    } catch (error) {
        console.error('Error loading points data:', error);
        return [];
    }
}

// Check points for a specific ID
async function checkPoints(userID) {
    const data = await loadPointsData();
    const user = data.find(u => u.ID === userID);
    return user || null;
}

// Add or update user points
function addOrUpdateUser(userID, points) {
    const existingIndex = pointsData.findIndex(u => u.ID === userID);

    if (existingIndex !== -1) {
        pointsData[existingIndex].Points = points;
    } else {
        pointsData.push({ ID: userID, Points: points });
    }

    return pointsData;
}

// Remove user
function removeUser(userID) {
    pointsData = pointsData.filter(u => u.ID !== userID);
    return pointsData;
}

// Add points to existing user
function addPoints(userID, pointsToAdd) {
    const user = pointsData.find(u => u.ID === userID);
    if (user) {
        user.Points += pointsToAdd;
    }
    return pointsData;
}

// Deduct points from user
function deductPoints(userID, pointsToDeduct) {
    const user = pointsData.find(u => u.ID === userID);
    if (user) {
        user.Points = Math.max(0, user.Points - pointsToDeduct);
    }
    return pointsData;
}

// Save points data (for admin use - requires backend in production)
function savePointsData() {
    // In a real application, this would send data to a backend server
    // For now, we'll just return the JSON string for download
    return JSON.stringify(pointsData, null, 4);
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        loadPointsData,
        checkPoints,
        addOrUpdateUser,
        removeUser,
        addPoints,
        deductPoints,
        savePointsData
    };
}
