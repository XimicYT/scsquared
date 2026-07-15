const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();
const http = require('http');
const { Server } = require('socket.io');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const rateLimit = require('express-rate-limit');
const webpush = require('web-push');
const Filter = require('bad-words'); // Import the filter
const filter = new Filter({ placeHolder: '#' }); // Configure it to use '#'

// 1. General API Rate Limiter
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10000,
    message: { error: "Too many requests from this IP, please try again after 15 minutes." },
    standardHeaders: true,
    legacyHeaders: false,
});

// 2. Strict Auth Limiter 
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: "Too many login attempts. Please try again later." }
});

// 3. Message/Attachment Limiter
const messageLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 30,
    message: { error: "You are sending messages too quickly. Slow down!" }
});

// --- Cloudinary Setup ---
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});
webpush.setVapidDetails(
    process.env.VAPID_SUBJECT,
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
);

// Helper function to send push notifications securely
async function sendPushNotification(userId, payload) {
    try {
        const { data: subscriptions } = await supabase
            .from('push_subscriptions')
            .select('*')
            .eq('user_id', userId);

        if (!subscriptions || subscriptions.length === 0) return;

        const pushPayload = JSON.stringify(payload);

        // Send to all of the user's registered devices
        await Promise.all(subscriptions.map(async (sub) => {
            const pushConfig = {
                endpoint: sub.endpoint,
                keys: { auth: sub.keys_auth, p256dh: sub.keys_p256dh }
            };

            try {
                await webpush.sendNotification(pushConfig, pushPayload);
            } catch (err) {
                // If the device unsubscribed or the token expired, delete it
                if (err.statusCode === 404 || err.statusCode === 410) {
                    await supabase.from('push_subscriptions').delete().eq('id', sub.id);
                }
            }
        }));
    } catch (err) {
        console.error("Push notification routing error:", err);
    }
}
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'sc_chat_attachments',
        allowed_formats: ['jpg', 'jpeg', 'png', 'gif', 'webp'],
        transformation: [{ width: 1000, crop: "limit", quality: "auto" }]
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed.'));
        }
    }
});

const app = express();
app.set('trust proxy', 1);

const PORT = process.env.PORT || 10000;
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: true,
        credentials: true
    },
    pingInterval: 10000,
    pingTimeout: 15000
});

const activeUsers = new Map();
const userStatuses = new Map(); // ADD THIS LINE
// Secure Socket Authentication Middleware
io.use((socket, next) => {
    const cookieHeader = socket.request.headers.cookie;
    if (!cookieHeader) return next(new Error('Authentication error: No cookies'));

    const cookies = {};
    cookieHeader.split(';').forEach(cookie => {
        const parts = cookie.split('=');
        cookies[parts[0].trim()] = parts[1] ? decodeURIComponent(parts[1].trim()) : '';
    });

    const token = cookies.sc_token;
    if (!token) return next(new Error('Authentication error: Token missing'));

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        socket.userId = decoded.id;
        next();
    } catch (err) {
        return next(new Error('Authentication error: Invalid token'));
    }
});

io.on('connection', (socket) => {

    // SECURE REGISTER: Relies on JWT userId, ignores client payload
    socket.on('register', () => {
        const userId = socket.userId;

        if (!activeUsers.has(userId)) {
            activeUsers.set(userId, new Set());
        }

        const userConnections = activeUsers.get(userId);

        // If this is their FIRST tab opening, tell everyone they are online
        if (userConnections.size === 0) {
            io.emit('user_status_update', { userId: userId, status: 'online' });
        }

        userConnections.add(socket.id);
    });
    socket.on('status_change', (data) => {
        const userId = socket.userId;

        if (userId) {
            userStatuses.set(userId, data.status);
            // 🔥 CRITICAL: Broadcast the update out so other users' UIs actually change!
            io.emit('user_status_update', { userId: userId, status: data.status });
        }
    });
    // MISSING FEATURE ADDED: Relays typing events to the specific user's active tabs
    socket.on('typing', (data) => {
        const receiverSockets = activeUsers.get(data.receiver_id);
        if (receiverSockets && receiverSockets.size > 0) {
            io.to([...receiverSockets]).emit('typing', {
                sender_id: socket.userId,
                username: data.username,
                isTyping: data.isTyping,
                receiver_id: data.receiver_id
            });
        }
    });

    socket.on('disconnect', () => {
        const userId = socket.userId;
        if (userId && activeUsers.has(userId)) {
            const userConnections = activeUsers.get(userId);
            userConnections.delete(socket.id);

            if (userConnections.size === 0) {
                activeUsers.delete(userId);
                userStatuses.delete(userId); // ADD THIS LINE to clean up
                io.emit('user_status_update', { userId: userId, status: 'offline' });
            }
        }
    });
});

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

app.use(cors({
    origin: function (origin, callback) {
        callback(null, true);
    },
    credentials: true
}));

app.use(express.json());
app.use('/api', apiLimiter);

app.use((req, res, next) => {
    req.cookies = {};
    const cookieHeader = req.headers.cookie;
    if (cookieHeader) {
        cookieHeader.split(';').forEach(cookie => {
            const parts = cookie.split('=');
            req.cookies[parts[0].trim()] = parts[1] ? decodeURIComponent(parts[1].trim()) : '';
        });
    }
    next();
});

function sanitizeInput(str) {
    if (typeof str !== 'string') return '';
    return str
        .trim()
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
}

function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function isValidUsername(username) {
    const usernameRegex = /^[a-zA-Z0-9_-]{3,20}$/;
    return usernameRegex.test(username);
}

async function generateUniqueChatId() {
    let attempts = 0;
    while (attempts < 10) {
        const randomId = Math.floor(100000 + Math.random() * 900000).toString();
        const { data } = await supabase
            .from('users')
            .select('chat_id')
            .eq('chat_id', randomId)
            .single();

        if (!data) return randomId;
        attempts++;
    }
    throw new Error('Failed to generate a unique Chat ID');
}

// Auth Routes
app.post('/api/auth/register', authLimiter, async (req, res) => {
    let { first_name, username, email, password } = req.body;
    if (!username || !password || !first_name || !email) {
        return res.status(400).json({ error: 'All fields are required.' });
    }
    first_name = sanitizeInput(first_name);
    username = sanitizeInput(username);
    email = email.trim().toLowerCase();

    if (first_name.length < 1 || first_name.length > 50) {
        return res.status(400).json({ error: 'First name must be between 1 and 50 characters.' });
    }
    if (!isValidUsername(username)) {
        return res.status(400).json({ error: 'Username must be 3-20 characters long.' });
    }
    if (!isValidEmail(email)) {
        return res.status(400).json({ error: 'Please present a valid email address.' });
    }
    if (password.length < 5) {
        return res.status(400).json({ error: 'Password must be at least 5 characters long.' });
    }

    try {
        const passwordHash = await bcrypt.hash(password, 10);
        const chatId = await generateUniqueChatId();

        const { data, error } = await supabase
            .from('users')
            .insert([{ first_name, username, email, password_hash: passwordHash, chat_id: chatId }])
            .select('id, username, chat_id, first_name')
            .single();

        if (error) {
            if (error.code === '23505') return res.status(400).json({ error: "That email or username is already taken." });
            throw error;
        }

        const token = jwt.sign({ id: data.id, username: data.username }, process.env.JWT_SECRET, { expiresIn: '24h' });
        res.cookie('sc_token', token, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000 });
        res.status(201).json({ message: 'User registered successfully', user: { ...data, bio: null } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
    let { login_identifier, password } = req.body;
    if (!login_identifier || !password) return res.status(400).json({ error: 'Please enter your credentials.' });
    login_identifier = sanitizeInput(login_identifier);

    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .or(`chat_id.eq.${login_identifier},username.eq.${login_identifier}`)
            .single();

        if (error || !user) throw new Error("Nope, that's not the right login.");
        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) throw new Error("Nope, that's not the right login.");

        const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '24h' });
        res.cookie('sc_token', token, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000 });
        res.status(200).json({ message: 'Login successful', user: { id: user.id, username: user.username, chat_id: user.chat_id, first_name: user.first_name, bio: user.bio } });
    } catch (err) {
        res.status(401).json({ error: err.message });
    }
});

app.get('/api/auth/verify', async (req, res) => {
    try {
        const token = req.cookies.sc_token;
        if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });
        const verifiedData = jwt.verify(token, process.env.JWT_SECRET);
        const { data: user, error } = await supabase.from('users').select('id').eq('id', verifiedData.id).single();
        if (error || !user) return res.status(401).json({ error: 'Session invalid.' });
        res.status(200).json({ authenticated: true });
    } catch (err) {
        res.status(401).json({ error: 'Invalid token.' });
    }
});

app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('sc_token', { httpOnly: true, secure: true, sameSite: 'None' });
    res.status(200).json({ message: 'Logged out cleanly.' });
});

const requireAuth = (req, res, next) => {
    const token = req.cookies.sc_token;
    if (!token) return res.status(401).json({ error: 'Unauthorized. Please log in.' });
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Session expired or invalid.' });
    }
};

app.put('/api/users/profile', requireAuth, async (req, res) => {
    const userId = req.user.id;
    let { bio, birth_month, birth_day, custom_color, timezone } = req.body;
    bio = sanitizeInput(bio);
    try {
        const { data, error } = await supabase.from('users').update({ bio, birth_month, birth_day, custom_color, timezone }).eq('id', userId).select('bio, birth_month, birth_day, custom_color, timezone').single();
        if (error) throw error;
        res.status(200).json({ message: 'Profile updated successfully', profile: data });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update profile.' });
    }
});

app.get('/health', (req, res) => {
    res.status(200).json({ status: 'OK', message: 'Server is awake!', timestamp: new Date().toISOString() });
});

// --- CONTACTS ROUTES ---
app.post('/api/contacts/add', requireAuth, async (req, res) => {
    const myId = req.user.id;
    try {
        const { data: friend, error: friendError } = await supabase.from('users').select('id, username').eq('chat_id', req.body.friend_chat_id).single();
        if (friendError || !friend) return res.status(404).json({ error: 'User not found.' });
        if (friend.id === myId) return res.status(400).json({ error: 'You cannot add yourself.' });

        const { data: existingContact } = await supabase.from('contacts').select('*').eq('user_id', myId).eq('contact_user_id', friend.id).single();
        if (existingContact) return res.status(400).json({ error: 'Already in contacts.' });

        const { error: insertError } = await supabase.from('contacts').insert([{ user_id: myId, contact_user_id: friend.id }, { user_id: friend.id, contact_user_id: myId }]);
        if (insertError) throw insertError;

        // FIXED: Spread Set into Array for io.to()
        const friendSockets = activeUsers.get(friend.id);
        if (friendSockets && friendSockets.size > 0) io.to([...friendSockets]).emit('contacts_updated');

        res.status(200).json({ message: `${friend.username} added!`, friend });
    } catch (err) {
        res.status(500).json({ error: 'Server error adding contact.' });
    }
});

app.get('/api/contacts', requireAuth, async (req, res) => {
    const myId = req.user.id;
    try {
        const { data: contacts, error } = await supabase
            .from('contacts')
            .select(`is_favorite, is_blocked, users!contacts_contact_user_id_fkey(id, username, chat_id, bio)`)
            .eq('user_id', myId);

        if (error) throw error;

        // Use Promise.all to fetch the latest message for each contact concurrently
        const formattedContacts = await Promise.all(contacts.map(async (c) => {
            const isOnline = activeUsers.has(c.users.id);

            // 🔥 ADD THIS: Grab their exact status if they are online, otherwise fallback to offline
            const exactStatus = isOnline ? (userStatuses.get(c.users.id) || 'online') : 'offline';

            // 1. Fetch the most recent message between you and this contact
            const { data: lastMsgData } = await supabase
                .from('messages')
                .select('message_text, attachment_url, sender_id')
                .or(`and(sender_id.eq.${myId},receiver_id.eq.${c.users.id}),and(sender_id.eq.${c.users.id},receiver_id.eq.${myId})`)
                .order('created_at', { ascending: false })
                .limit(1)
                .single();

            // 2. Format the preview text (handle image-only messages safely)
            let previewText = "";
            let senderId = null;

            if (lastMsgData) {
                previewText = lastMsgData.message_text || (lastMsgData.attachment_url ? '📸 Image' : '');
                senderId = lastMsgData.sender_id;
            }

            // 3. Return the fully assembled contact object
            return {
                ...c.users,
                is_favorite: c.is_favorite,
                is_blocked: c.is_blocked,
                last_message: previewText,
                last_message_sender_id: senderId,
                current_status: exactStatus  // 🔥 CHANGE THIS LINE to use exactStatus
            };
        }));

        res.status(200).json({ contacts: formattedContacts });
    } catch (err) {
        console.error("Error fetching contacts:", err);
        res.status(500).json({ error: 'Server error fetching contacts.' });
    }
});

app.delete('/api/contacts/:contact_id', requireAuth, async (req, res) => {
    const myId = req.user.id;
    const contactId = req.params.contact_id;
    try {
        await supabase.from('contacts').delete().match({ user_id: myId, contact_user_id: contactId });
        await supabase.from('contacts').delete().match({ user_id: contactId, contact_user_id: myId });

        // FIXED: Spread Set into Array for io.to()
        const friendSockets = activeUsers.get(contactId);
        if (friendSockets && friendSockets.size > 0) io.to([...friendSockets]).emit('contacts_updated');

        res.status(200).json({ message: 'Contact removed.' });
    } catch (err) {
        res.status(500).json({ error: 'Server error removing contact.' });
    }
});

app.patch('/api/contacts/:id/block', async (req, res) => {
    const myId = req.cookies.sc_token ? jwt.verify(req.cookies.sc_token, process.env.JWT_SECRET).id : null;
    if (!myId) return res.status(401).json({ error: "Unauthorized" });
    try {
        const { data, error } = await supabase.from('contacts').update({ is_blocked: req.body.is_blocked }).eq('user_id', myId).eq('contact_user_id', req.params.id).select().single();
        if (error) throw error;
        res.json({ success: true, contact: data });
    } catch (err) {
        res.status(500).json({ error: "Could not update block status." });
    }
});

app.delete('/api/contacts/:id', async (req, res) => {
    const myId = req.cookies.sc_token ? jwt.verify(req.cookies.sc_token, process.env.JWT_SECRET).id : null;
    if (!myId) return res.status(401).json({ error: "Unauthorized" });
    try {
        await supabase.from('contacts').delete().eq('user_id', myId).eq('contact_user_id', req.params.id);
        res.json({ success: true, message: "Contact removed" });
    } catch (err) {
        res.status(500).json({ error: "Could not remove contact." });
    }
});

app.patch('/api/contacts/favorite', requireAuth, async (req, res) => {
    try {
        const { error } = await supabase.from('contacts').update({ is_favorite: req.body.is_favorite }).match({ user_id: req.user.id, contact_user_id: req.body.contact_id });
        if (error) throw error;
        res.status(200).json({ message: 'Favorites updated.' });
    } catch (err) {
        res.status(500).json({ error: 'Server error updating favorites.' });
    }
});
app.post('/api/notifications/subscribe', requireAuth, async (req, res) => {
    const myId = req.user.id;
    const { subscription } = req.body;

    if (!subscription || !subscription.endpoint) {
        return res.status(400).json({ error: "Invalid subscription payload." });
    }

    try {
        // Upsert the subscription (handles if the same device sends it twice)
        const { error } = await supabase.from('push_subscriptions').upsert({
            user_id: myId,
            endpoint: subscription.endpoint,
            keys_auth: subscription.keys.auth,
            keys_p256dh: subscription.keys.p256dh
        }, { onConflict: 'endpoint' });

        if (error) throw error;
        res.status(200).json({ success: true, message: "Device registered for push." });
    } catch (err) {
        res.status(500).json({ error: "Failed to save push subscription." });
    }
});
// Generic endpoint to trigger a notification from the frontend
app.post('/api/notifications/trigger', requireAuth, async (req, res) => {
    const { receiver_id, title, body, url } = req.body;

    if (!receiver_id || !title) {
        return res.status(400).json({ error: "Missing required notification fields." });
    }

    try {
        const receiverSockets = activeUsers.get(receiver_id);
        const receiverStatus = userStatuses.get(receiver_id) || 'offline'; // Grab their exact status

        // Send push if they are offline (no sockets) OR if they are marked as away/inactive
        if (!receiverSockets || receiverSockets.size === 0 || receiverStatus === 'away' || receiverStatus === 'inactive') {
            await sendPushNotification(receiver_id, {
                title: title,
                body: body || 'You have a new notification',
                url: url || '/'
            });
        } else {
            // 🔥 NEW: User is ONLINE. Send in-app notification to all their active tabs
            for (const socketId of receiverSockets) {
                io.to(socketId).emit('in_app_notification', {
                    title: title,
                    body: body || 'You have a new message',
                    url: url || '/'
                });
            }
        }

        res.status(200).json({ success: true, message: "Notification processed." });
    } catch (err) {
        console.error("Error triggering notification:", err);
        res.status(500).json({ error: "Failed to trigger notification." });
    }
});
// --- MESSAGES API ---
app.get('/api/messages/:contactId', requireAuth, async (req, res) => {
    const myId = req.user.id;
    try {
        const { data: messages, error } = await supabase.from('messages').select('*').or(`and(sender_id.eq.${myId},receiver_id.eq.${req.params.contactId}),and(sender_id.eq.${req.params.contactId},receiver_id.eq.${myId})`).order('created_at', { ascending: true });
        if (error) throw error;
        res.status(200).json(messages);
    } catch (err) {
        res.status(500).json({ error: 'Failed to load messages.' });
    }
});

app.post('/api/messages', messageLimiter, requireAuth, (req, res, next) => {
    upload.single('attachment')(req, res, (err) => {
        if (err) return res.status(400).json({ error: err.message });
        next();
    });
}, async (req, res) => {
    const myId = req.user.id;
    const { receiver_id } = req.body;
    let { message_text } = req.body; // Changed to let so we can filter it

    if (!receiver_id) return res.status(400).json({ error: "Missing receiver." });
    if (!message_text && !req.file) return res.status(400).json({ error: "Content required." });
    if (message_text && message_text.length > 2000) return res.status(400).json({ error: "Message exceeds 2,000 characters." });

    // Apply the bad-words filter safely
    if (message_text && typeof message_text === 'string') {
        try {
            message_text = filter.clean(message_text);
        } catch (err) {
            // If bad-words crashes on emojis/symbols, just ignore and keep original text
            console.warn("bad-words skipped a symbol-only message");
        }
    }

    const attachmentUrl = req.file ? req.file.path : null;
    try {
        const { data: blockCheck } = await supabase.from('contacts').select('user_id, is_blocked').or(`and(user_id.eq.${myId},contact_user_id.eq.${receiver_id}),and(user_id.eq.${receiver_id},contact_user_id.eq.${myId})`).eq('is_blocked', true);
        if (blockCheck && blockCheck.length > 0) {
            if (blockCheck.some(b => b.user_id === myId)) {
                return res.status(403).json({ error: "You have blocked this user." });
            }
            return res.status(403).json({ error: "Message failed to send." });
        }

        const { data: newMessage, error } = await supabase.from('messages').insert([{ sender_id: myId, receiver_id, message_text: message_text || "", attachment_url: attachmentUrl, is_read: false }]).select().single();
        if (error) throw error;

        // FIXED: Spread Set into Array for io.to()
        const receiverSockets = activeUsers.get(receiver_id);
        if (receiverSockets && receiverSockets.size > 0) io.to([...receiverSockets]).emit('receive_message', newMessage);

        res.status(201).json(newMessage);
    } catch (err) {
        res.status(500).json({ error: 'Failed to send message.' });
    }
});

// ==========================================
// 👥 GROUP CHATS API ENDPOINTS
// ==========================================

// 1. GET All Groups for the Logged-in User
app.get('/api/groups', requireAuth, async (req, res) => {
    const myId = req.user.id;
    try {
        const { data: memberships, error } = await supabase
            .from('group_members')
            .select(`
                group_id,
                groups (
                    id,
                    name,
                    description,
                    created_at,
                    created_by
                )
            `)
            .eq('user_id', myId)
            .eq('status', 'joined');

        if (error) throw error;

        const groups = (memberships || [])
            .filter(m => m.groups !== null)
            .map(m => m.groups);

        res.status(200).json(groups);
    } catch (err) {
        console.error("Error fetching groups:", err);
        res.status(500).json({ error: "Could not fetch groups." });
    }
});

// 2. Fetch pending group invites for the user
app.get('/api/groups/invites', requireAuth, async (req, res) => {
    const myId = req.user.id;
    try {
        const { data: invites, error } = await supabase
            .from('group_members')
            .select(`
                group_id,
                groups(id, name, description, created_at, users!groups_created_by_fkey(username))
            `)
            .eq('user_id', myId)
            .eq('status', 'invited');

        if (error) throw error;

        const formattedInvites = (invites || [])
            .filter(i => i.groups !== null)
            .map(i => ({
                id: i.groups.id,
                name: i.groups.name,
                description: i.groups.description,
                invited_by: i.groups.users?.username || "Unknown"
            }));

        res.json({ invites: formattedInvites });
    } catch (err) {
        res.status(500).json({ error: "Failed to load pending invitations." });
    }
});

// 3. Create group chat 
app.post('/api/groups', requireAuth, async (req, res) => {
    const myId = req.user.id;
    let { name, description, members } = req.body;

    name = sanitizeInput(name);
    description = description ? sanitizeInput(description) : "A new group chat";

    if (!name || name.length < 1 || name.length > 50) {
        return res.status(400).json({ error: "Please enter a group title between 1 and 50 characters." });
    }

    try {
        const { data: group, error: groupError } = await supabase
            .from('groups')
            .insert([{ name, description, created_by: myId }])
            .select()
            .single();

        if (groupError) throw groupError;

        let memberIds = Array.isArray(members) ? members : [];
        if (!memberIds.includes(myId)) memberIds.push(myId);
        memberIds = [...new Set(memberIds)];

        const membersToInsert = memberIds.map(id => ({
            group_id: group.id,
            user_id: id,
            status: id === myId ? 'joined' : 'invited'
        }));

        const { error: memberError } = await supabase.from('group_members').insert(membersToInsert);
        if (memberError) throw memberError;

        memberIds.forEach(targetId => {
            if (targetId !== myId) {
                // FIXED: Spread Set into Array for io.to()
                const receiverSockets = activeUsers.get(targetId);
                if (receiverSockets && receiverSockets.size > 0) io.to([...receiverSockets]).emit('group_invite_received');
            }
        });

        res.status(201).json({ success: true, group });
    } catch (err) {
        res.status(500).json({ error: "Could not create group. Try again later." });
    }
});

// 4. Invite user by Tag
app.post('/api/groups/:id/invite', requireAuth, async (req, res) => {
    const groupId = req.params.id;
    let { user_tag } = req.body;
    user_tag = sanitizeInput(user_tag);

    try {
        const { data: group, error: groupErr } = await supabase.from('groups').select('created_by').eq('id', groupId).single();
        if (groupErr || !group) return res.status(404).json({ error: "No group found with that ID." });

        if (group.created_by !== req.user.id) {
            return res.status(403).json({ error: "Access Denied: Only the original group creator can manage invitations." });
        }

        const { data: targetUser, error: userError } = await supabase.from('users').select('id, username').eq('chat_id', user_tag).single();
        if (userError || !targetUser) return res.status(404).json({ error: "No user found with that Tag ID." });

        const { data: existing } = await supabase.from('group_members').select('status').eq('group_id', groupId).eq('user_id', targetUser.id).single();
        if (existing) {
            if (existing.status === 'joined') return res.status(400).json({ error: "User is already a member of this group." });
            if (existing.status === 'invited') return res.status(400).json({ error: "An invitation has already been sent to this user." });
        }

        const { error: inviteError } = await supabase.from('group_members').insert([{ group_id: groupId, user_id: targetUser.id, status: 'invited' }]);
        if (inviteError) throw inviteError;

        // FIXED: Spread Set into Array for io.to()
        const receiverSockets = activeUsers.get(targetUser.id);
        if (receiverSockets && receiverSockets.size > 0) io.to([...receiverSockets]).emit('group_invite_received');

        res.json({ success: true, message: `Successfully invited ${targetUser.username}!` });
    } catch (err) {
        res.status(500).json({ error: "Failed to process invitation." });
    }
});

// 4.5. Update Group Settings (Creator Only)
app.patch('/api/groups/:id', requireAuth, async (req, res) => {
    const groupId = req.params.id;
    const myId = req.user.id;
    let { name, description } = req.body;

    name = sanitizeInput(name);
    description = description ? sanitizeInput(description) : "";

    if (!name || name.length < 1 || name.length > 50) {
        return res.status(400).json({ error: "Title must be between 1 and 50 characters." });
    }

    try {
        const { data: group, error: checkErr } = await supabase.from('groups').select('created_by').eq('id', groupId).single();
        if (checkErr || !group) return res.status(404).json({ error: "Group not found." });
        if (group.created_by !== myId) return res.status(403).json({ error: "Access Denied: Only the creator can modify settings." });

        const { data: updatedGroup, error: updateErr } = await supabase
            .from('groups')
            .update({ name, description })
            .eq('id', groupId)
            .select()
            .single();

        if (updateErr) throw updateErr;

        io.to(`group_${groupId}`).emit('group_settings_updated', updatedGroup);

        res.json({ success: true, group: updatedGroup });
    } catch (err) {
        res.status(500).json({ error: "Could not update group settings." });
    }
});

// 4.6. Delete Group (Creator Only)
app.delete('/api/groups/:id', requireAuth, async (req, res) => {
    const groupId = req.params.id;
    const myId = req.user.id;

    try {
        const { data: group, error: checkErr } = await supabase.from('groups').select('created_by').eq('id', groupId).single();
        if (checkErr || !group) return res.status(404).json({ error: "Group not found." });
        if (group.created_by !== myId) return res.status(403).json({ error: "Access Denied: Only the creator can delete this group." });

        // Delete dependencies safely
        await supabase.from('group_members').delete().eq('group_id', groupId);
        await supabase.from('group_messages').delete().eq('group_id', groupId);

        const { error: deleteErr } = await supabase.from('groups').delete().eq('id', groupId);
        if (deleteErr) throw deleteErr;

        io.to(`group_${groupId}`).emit('group_deleted', groupId);

        res.json({ success: true, message: "Group deleted successfully." });
    } catch (err) {
        res.status(500).json({ error: "Could not delete group." });
    }
});

// 4.7. Leave Group (Members Only)
app.post('/api/groups/:id/leave', requireAuth, async (req, res) => {
    const groupId = req.params.id;
    const myId = req.user.id;

    try {
        const { data: group, error: checkErr } = await supabase.from('groups').select('created_by').eq('id', groupId).single();
        if (checkErr || !group) return res.status(404).json({ error: "Group not found." });
        if (group.created_by === myId) return res.status(400).json({ error: "Creators cannot leave. Transfer ownership or delete the group." });

        const { error: leaveErr } = await supabase
            .from('group_members')
            .delete()
            .eq('group_id', groupId)
            .eq('user_id', myId);

        if (leaveErr) throw leaveErr;

        io.to(`group_${groupId}`).emit('group_members_updated', groupId);

        res.json({ success: true, message: "You have left the group." });
    } catch (err) {
        res.status(500).json({ error: "Could not leave group." });
    }
});

// 5. NEW: Get All Group Members
app.get('/api/groups/:id/members', requireAuth, async (req, res) => {
    const groupId = req.params.id;
    const myId = req.user.id;
    try {
        const { data: membership, error: checkError } = await supabase.from('group_members').select('status').eq('group_id', groupId).eq('user_id', myId).single();
        if (checkError || !membership || membership.status !== 'joined') {
            return res.status(403).json({ error: "Access denied. You are not an active member of this room." });
        }

        const { data: members, error } = await supabase
            .from('group_members')
            .select(`user_id, status, joined_at, users (id, username, chat_id)`)
            .eq('group_id', groupId);

        if (error) throw error;

        const { data: group } = await supabase.from('groups').select('created_by').eq('id', groupId).single();

        res.json({
            creator_id: group ? group.created_by : null,
            members: (members || []).filter(m => m.users !== null).map(m => ({
                id: m.users.id,
                username: m.users.username,
                chat_id: m.users.chat_id,
                status: m.status,
                joined_at: m.joined_at
            }))
        });
    } catch (err) {
        res.status(500).json({ error: "Failed to retrieve member log files." });
    }
});

// 6. NEW: Secure Member Deletion Route (Creator Only)
app.delete('/api/groups/:id/members/:memberId', requireAuth, async (req, res) => {
    const groupId = req.params.id;
    const memberId = req.params.memberId;
    const myId = req.user.id;

    try {
        const { data: group, error: groupError } = await supabase.from('groups').select('created_by').eq('id', groupId).single();
        if (groupError || !group) return res.status(404).json({ error: "Target channel does not exist." });

        if (group.created_by !== myId) {
            return res.status(403).json({ error: "Access Denied: Only the original group creator can remove users." });
        }

        if (String(memberId) === String(myId)) {
            return res.status(400).json({ error: "The infrastructure creator cannot be evicted from the group matrix." });
        }

        const { error: deleteError } = await supabase.from('group_members').delete().eq('group_id', groupId).eq('user_id', memberId);
        if (deleteError) throw deleteError;

        // FIXED: Spread Set into Array for io.to()
        const targetSockets = activeUsers.get(memberId);
        if (targetSockets && targetSockets.size > 0) {
            io.to([...targetSockets]).emit('group_removed', groupId);
        }

        io.to(`group_${groupId}`).emit('group_members_updated', groupId);
        res.json({ success: true, message: "Member terminated and cleared from channel data structures." });
    } catch (err) {
        res.status(500).json({ error: "System failure during member deletion routine." });
    }
});

// 7. Accept a persistent group invitation
app.post('/api/groups/:id/accept', requireAuth, async (req, res) => {
    const groupId = req.params.id;
    const myId = req.user.id;
    try {
        const { error } = await supabase.from('group_members').update({ status: 'joined', joined_at: new Date() }).eq('group_id', groupId).eq('user_id', myId).eq('status', 'invited');
        if (error) throw error;
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: "Could not accept invitation." });
    }
});

// 8. Decline/Delete a group invitation
app.post('/api/groups/:id/decline', requireAuth, async (req, res) => {
    const groupId = req.params.id;
    const myId = req.user.id;
    try {
        const { error } = await supabase.from('group_members').delete().eq('group_id', groupId).eq('user_id', myId).eq('status', 'invited');
        if (error) throw error;
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: "Could not remove invitation." });
    }
});

// 9. Get message history for a group chat
app.get('/api/groups/:id/messages', requireAuth, async (req, res) => {
    try {
        const { data: messages, error } = await supabase.from('group_messages').select(`id, message_text, attachment_url, created_at, sender_id, users(username)`).eq('group_id', req.params.id).order('created_at', { ascending: true });
        if (error) throw error;
        res.json({ messages });
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch chat history." });
    }
});

// 10. Send group message
app.post('/api/groups/:id/messages', messageLimiter, requireAuth, (req, res, next) => {
    upload.single('attachment')(req, res, (err) => {
        if (err) return res.status(400).json({ error: err.message });
        next();
    });
}, async (req, res) => {
    const groupId = req.params.id;
    const myId = req.user.id;
    let { message_text } = req.body; // Changed to let so we can filter it

    if (!message_text && !req.file) return res.status(400).json({ error: "Message content or an image is required." });
    if (message_text && message_text.length > 2000) return res.status(400).json({ error: "Message exceeds 2,000 character limit." });

    // Apply the bad-words filter safely
    if (message_text && typeof message_text === 'string') {
        try {
            message_text = filter.clean(message_text);
        } catch (err) {
            // If bad-words crashes on emojis/symbols, just ignore and keep original text
            console.warn("bad-words skipped a symbol-only message");
        }
    }

    const attachmentUrl = req.file ? req.file.path : null;
    try {
        const { data: member } = await supabase.from('group_members').select('status').eq('group_id', groupId).eq('user_id', myId).single();
        if (!member || member.status !== 'joined') {
            return res.status(403).json({ error: "You are not an active member of this group." });
        }

        const { data: newMessage, error } = await supabase.from('group_messages').insert([{ group_id: groupId, sender_id: myId, message_text: message_text || "", attachment_url: attachmentUrl }]).select(`id, message_text, attachment_url, created_at, sender_id, users(username)`).single();
        if (error) throw error;

        io.to(`group_${groupId}`).emit('receive_group_message', newMessage);
        res.status(201).json(newMessage);
    } catch (err) {
        res.status(500).json({ error: 'Failed to send group message.' });
    }
});
// ==========================================
// 📊 POLLS API ENDPOINTS & LOGIC
// ==========================================

// 1. Create a new poll
app.post('/api/polls', requireAuth, async (req, res) => {
    const { question, options } = req.body;
    const myId = req.user.id;

    // Basic validation
    if (!question || !Array.isArray(options) || options.length < 2) {
        return res.status(400).json({ error: "Invalid poll data. Need a question and at least 2 options." });
    }

    try {
        const { data: poll, error } = await supabase
            .from('polls')
            .insert([{ creator_id: myId, question, options }])
            .select()
            .single();

        if (error) throw error;
        res.status(201).json(poll);
    } catch (err) {
        console.error("Poll Creation Error:", err);
        res.status(500).json({ error: "Failed to create poll." });
    }
});

// 2. Fetch poll details and all votes
app.get('/api/polls/:id', requireAuth, async (req, res) => {
    try {
        // Fetch the poll
        const { data: poll, error: pollError } = await supabase
            .from('polls')
            .select('*')
            .eq('id', req.params.id)
            .single();

        if (pollError) throw pollError;

        // Fetch all votes associated with it
        const { data: votes, error: votesError } = await supabase
            .from('poll_votes')
            .select('user_id, option_index')
            .eq('poll_id', req.params.id);

        if (votesError) throw votesError;

        res.status(200).json({ poll, votes });
    } catch (err) {
        res.status(500).json({ error: "Failed to load poll data." });
    }
});

// 3. Cast or change a vote
app.post('/api/polls/:id/vote', requireAuth, async (req, res) => {
    const pollId = req.params.id;
    const myId = req.user.id;
    const { option_index } = req.body;

    if (option_index === undefined || option_index === null) {
        return res.status(400).json({ error: "Missing option index." });
    }

    try {
        // Check if the user has already voted on this specific poll
        const { data: existingVote } = await supabase
            .from('poll_votes')
            .select('id')
            .eq('poll_id', pollId)
            .eq('user_id', myId)
            .single();

        if (existingVote) {
            // Update their existing vote
            await supabase.from('poll_votes').update({ option_index }).eq('id', existingVote.id);
        } else {
            // Insert a new vote
            await supabase.from('poll_votes').insert([{ poll_id: pollId, user_id: myId, option_index }]);
        }

        // 🔥 THE MAGIC: Broadcast to all active clients that this specific poll updated!
        // The frontend widgets will listen to this and silently re-fetch if they are currently rendering this poll.
        io.emit('poll_updated', pollId);

        res.status(200).json({ success: true });
    } catch (err) {
        console.error("Vote Error:", err);
        res.status(500).json({ error: "Failed to cast vote." });
    }
});
server.listen(PORT, () => {
    console.log(`Server running smoothly on port ${PORT}`);
});
