# Fast Client Groups Feature - Version 2.4

## Overview
The Fast Connection Client now supports group chat functionality, allowing users to create and join separate chat rooms.

## New Group Features

### **Group Management**

The Groups section includes:
- **Current Group dropdown** - Shows and switches between groups
- **Create Group button** - Create a new chat group
- **Join Group button** - Join an existing group
- **Leave Group button** - Leave current group and return to Global Chat

### **How Groups Work**

**Global Chat:**
- Default chat room for all connected users
- Everyone sees messages sent here
- No need to join - always available

**Private Groups:**
- Created by any user
- Only members see group messages
- Can have multiple groups active
- Messages tagged with group name

## Usage Guide

### **Creating a Group**

1. Connect to server
2. Click "Create Group"
3. Enter group name (e.g., "Team Alpha")
4. Click OK
5. ✅ Group created and you're automatically joined
6. Group appears in dropdown

### **Joining a Group**

**Method 1: Join Button**
1. Click "Join Group"
2. Dialog shows available groups
3. Enter group name
4. Click OK
5. ✅ Joined group

**Method 2: Dropdown**
1. Click "Current Group" dropdown
2. Select group from list
3. ✅ Automatically joined

### **Leaving a Group**

**Method 1: Leave Button**
1. Click "Leave Group"
2. ✅ Return to Global Chat

**Method 2: Dropdown**
1. Select "Global Chat" from dropdown
2. ✅ Automatically leave current group

### **Sending Messages**

Messages are sent to your current group:

**In Global Chat:**
```
You: Hello everyone!
Alice: Hi there!
```

**In a Group:**
```
[Team Alpha] You: Team meeting at 3pm
[Team Alpha] Bob: Got it!
```

## Interface

```
┌─────────────────────────────────────┐
│ User Information                    │
│ Username: [John]                    │
├─────────────────────────────────────┤
│ Connection                          │
│ Server Host: [192.168.1.100]        │
│ Server Port: [8000]                 │
│ [Connect] [Disconnect]              │
├─────────────────────────────────────┤
│ Groups                              │
│ Current Group: [Team Alpha ▼]       │
│ [Create Group] [Join] [Leave]       │
├─────────────────────────────────────┤
│ Messaging                           │
│ Message: [Type here...]             │
│ [Send Message]                      │
├─────────────────────────────────────┤
│ Chat                                │
│ Connected as John                   │
│ You are in: Global Chat             │
│ 📢 Alice created group: Team Alpha  │
│ ✓ Joined group: Team Alpha          │
│ [Team Alpha] You: Hello team!       │
│ 👋 Bob joined Team Alpha            │
│ [Team Alpha] Bob: Hi John!          │
│ ✓ Left group: Team Alpha            │
│ You: Back in global chat            │
└─────────────────────────────────────┘
```

## Message Types

### **Chat Messages**
```json
{
  "type": "chat",
  "username": "John",
  "message": "Hello!",
  "group": "Team Alpha"  // null for global
}
```

### **Group Created**
```json
{
  "type": "create_group",
  "group_name": "Team Alpha",
  "creator": "John"
}
```

### **User Joined**
```json
{
  "type": "join_group",
  "group_name": "Team Alpha",
  "username": "Alice"
}
```

### **User Left**
```json
{
  "type": "leave_group",
  "group_name": "Team Alpha",
  "username": "Bob"
}
```

## Example Scenarios

### **Scenario 1: Team Collaboration**

**John (Team Lead):**
1. Connects as "John"
2. Creates group "Project X"
3. Sends: "Team, let's discuss the project"

**Alice (Team Member):**
1. Connects as "Alice"
2. Sees: "📢 John created group: Project X"
3. Joins "Project X"
4. Sends: "Ready to discuss!"

**Bob (Team Member):**
1. Connects as "Bob"
2. Selects "Project X" from dropdown
3. Auto-joins group
4. Participates in discussion

### **Scenario 2: Multiple Groups**

**User manages multiple groups:**
1. In "Global Chat" - general announcements
2. Switches to "Team Alpha" - team discussions
3. Switches to "Developers" - technical talk
4. Back to "Global Chat" - public messages

Each group maintains separate conversations!

## Features

✅ **Create unlimited groups**
✅ **Join multiple groups** (switch between them)
✅ **Auto-join on creation**
✅ **Group notifications** (created, joined, left)
✅ **Message tagging** with group name
✅ **Dropdown quick-switch**
✅ **Global chat always available**
✅ **Visual indicators** (emojis for events)

## Benefits

### **Organization**
- Separate conversations by topic
- Keep discussions focused
- Reduce noise in global chat

### **Privacy**
- Only group members see messages
- Create private team channels
- Control who participates

### **Flexibility**
- Switch groups instantly
- Join/leave as needed
- Multiple groups per user

### **Collaboration**
- Team-specific discussions
- Project-based channels
- Department communications

## Visual Indicators

- 📢 Group created announcement
- ✓ Action confirmation (joined, left, created)
- 👋 User join/leave notifications
- [GroupName] Message prefix for group chats

## Technical Details

### **Group State Management**
- `current_group`: Currently active group (None = Global)
- `groups`: List of all available groups
- Auto-updates when groups created

### **Message Routing**
- Messages include `group` field
- Server routes to group members only
- Global messages have `group: null`

### **UI Updates**
- Dropdown auto-updates with new groups
- Leave button enabled/disabled based on state
- Real-time group list synchronization

## Tips

💡 **Create descriptive group names** - "Marketing Team" not "Group1"
💡 **Use Global Chat for announcements** - Everyone sees it
💡 **Switch groups via dropdown** - Faster than Join button
💡 **Leave groups you don't need** - Keeps list clean
💡 **Check current group before sending** - Avoid wrong channel messages

## Version History

### Version 2.4 (Current)
- ✅ Added group creation
- ✅ Added group joining/leaving
- ✅ Added group dropdown selector
- ✅ Added group message tagging
- ✅ Added group notifications
- ✅ Increased window size to 700x600

### Version 2.3
- Added Randomize button for encryption parameters
- Added Show/Hide password button
- Created Fast Connection Client

Perfect for team collaboration and organized communication!
