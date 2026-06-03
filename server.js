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

// 1. General API Rate Limiter
// Applies to most routes: allows 100 requests per 15 minutes per IP
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per `window`
    message: { error: "Too many requests from this IP, please try again after 15 minutes." },
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// 2. Strict Auth Limiter 
// Protects your Supabase DB from brute-force login/registration spam
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Limit each IP to 10 login/register requests per window
    message: { error: "Too many login attempts. Please try again later." }
});

// 3. Message/Attachment Limiter
// Prevents someone from writing a script to spam messages and fill up your Cloudinary/Supabase
const messageLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 30, // Limit each IP to 30 messages per minute
    message: { error: "You are sending messages too quickly. Slow down!" }
});
// --- Cloudinary Setup ---
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'sc_chat_attachments',
        allowed_formats: ['jpg', 'jpeg', 'png', 'gif', 'webp'],
        transformation: [{ width: 1000, crop: "limit", quality: "auto" }] // <-- ADD THIS
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed.'));
        }
    }
});
const app = express();
const PORT = process.env.PORT || 10000;
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: true,
        credentials: true
    }
});

// A local tracker mapping user database IDs to their active live connection socket
const activeUsers = new Map();

// 🔒 FIX 1: Secure Socket Authentication Middleware
io.use((socket, next) => {
    const cookieHeader = socket.request.headers.cookie;
    if (!cookieHeader) return next(new Error('Authentication error: No cookies'));

    // Manual cookie parser for the websocket connection
    const cookies = {};
    cookieHeader.split(';').forEach(cookie => {
        const parts = cookie.split('=');
        cookies[parts[0].trim()] = parts[1] ? decodeURIComponent(parts[1].trim()) : '';
    });

    const token = cookies.sc_token;
    if (!token) return next(new Error('Authentication error: Token missing'));

    try {
        // Verify the JWT exactly like the REST API does
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        socket.userId = decoded.id; // Secretly attach the verified database ID
        next();
    } catch (err) {
        return next(new Error('Authentication error: Invalid token'));
    }
});

io.on('connection', (socket) => {
    // 🔒 We no longer wait for the client to tell us who they are. We KNOW who they are.
    activeUsers.set(socket.userId, socket.id);

    // ⚡ FIX 2: O(1) Disconnect! No more loops.
    socket.on('disconnect', () => {
        activeUsers.delete(socket.userId);
    });
});

// Initialize Supabase Client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

app.use(cors({
    origin: function (origin, callback) {
        // By passing 'true' back, we dynamically allow whatever origin made the request.
        // NOTE: Change this back to an array of specific URLs before final production!
        callback(null, true);
    },
    credentials: true // Crucial to allow cross-origin HttpOnly cookies
}));

app.use(express.json());
app.use('/api', apiLimiter); // <-- ADD THIS LINE
// 🌟 Lightweight Cookie Parser Middleware (No external dependency needed)
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

// 🌟 INPUT SANITIZATION UTILITY (Prevents Stored XSS Injection)
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

// 🌟 BACKEND STRUCTURAL INPUT VALIDATORS
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function isValidUsername(username) {
    // Alphanumeric, underscores, or hyphens; 3-20 characters long
    const usernameRegex = /^[a-zA-Z0-9_-]{3,20}$/;
    return usernameRegex.test(username);
}

// Helper function to generate a truly unique 6-digit ID
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

// 1. REGISTER ENDPOINT (With Validation, Sanitization & Cookie Delivery)
app.post('/api/auth/register', authLimiter, async (req, res) => {
    let { first_name, username, email, password } = req.body;

    if (!username || !password || !first_name || !email) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    // Sanitize and normalize string inputs
    first_name = sanitizeInput(first_name);
    username = sanitizeInput(username);
    email = email.trim().toLowerCase();

    // server.js - Inside the /api/auth/register route

    // Execute backend integrity checks
    if (first_name.length < 1 || first_name.length > 50) {
        return res.status(400).json({ error: 'First name must be between 1 and 50 characters.' });
    }
    if (!isValidUsername(username)) {
        return res.status(400).json({ error: 'Username must be 3-20 characters long and contain only alphanumeric characters, underscores, or hyphens.' });
    }
    if (!isValidEmail(email)) {
        return res.status(400).json({ error: 'Please present a valid email address.' });
    }

    // 🌟 FIX 3: Balanced Password Rule for Casual Use
    if (password.length < 5) {
        return res.status(400).json({ error: 'Password must be at least 5 characters long.' });
    }

    try {
        const passwordHash = await bcrypt.hash(password, 10);
        const chatId = await generateUniqueChatId();

        const { data, error } = await supabase
            .from('users')
            .insert([{
                first_name: first_name,
                username: username,
                email: email,
                password_hash: passwordHash,
                chat_id: chatId
            }])
            .select('id, username, chat_id, first_name')
            .single();

        if (error) {
            if (error.code === '23505') {
                return res.status(400).json({ error: "That email or username is already taken." });
            }
            throw error;
        }

        // Auto-login upon registration: Create token
        const token = jwt.sign(
            { id: data.id, username: data.username },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Deliver token safely hidden inside HttpOnly cookie
        res.cookie('sc_token', token, {
            httpOnly: true,
            secure: true,       // Enforces HTTPS (Render handles this natively)
            sameSite: 'None',   // Required for cross-site cookie transit
            maxAge: 24 * 60 * 60 * 1000 // 24 Hours
        });

        res.status(201).json({
            message: 'User registered successfully',
            user: {
                id: data.id,
                username: data.username,
                chat_id: data.chat_id,
                first_name: data.first_name,
                bio: null // Explicitly null so the frontend knows setup is pending
            }
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. LOGIN ENDPOINT (Generates secure HttpOnly Cookie)
app.post('/api/auth/login', authLimiter, async (req, res) => {
    let { login_identifier, password } = req.body;

    if (!login_identifier || !password) {
        return res.status(400).json({ error: 'Please enter your tag or display name, and password.' });
    }

    login_identifier = sanitizeInput(login_identifier);

    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .or(`chat_id.eq.${login_identifier},username.eq.${login_identifier}`)
            .single();

        if (error || !user) {
            throw new Error("Nope, that's not the right login.");
        }

        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) {
            throw new Error("Nope, that's not the right login.");
        }

        // Generate the token payload
        const token = jwt.sign(
            { id: user.id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Bake cookie directly into response headers
        res.cookie('sc_token', token, {
            httpOnly: true,
            secure: true,
            sameSite: 'None',
            maxAge: 24 * 60 * 60 * 1000
        });

        // Token is cleanly absent from the response body payload!
        res.status(200).json({
            message: 'Login successful',
            user: {
                id: user.id,
                username: user.username,
                chat_id: user.chat_id,
                first_name: user.first_name,
                bio: user.bio // This powers our refresh guard!
            }
        });
    } catch (err) {
        res.status(401).json({ error: err.message });
    }
});

// 3. SECURE VERIFICATION ENDPOINT (Reads Cookie)
app.get('/api/auth/verify', async (req, res) => {
    try {
        // Read cookie value extracted from header by middleware
        const token = req.cookies.sc_token;

        if (!token) {
            return res.status(401).json({ error: 'Access denied. No token provided.' });
        }

        const verifiedData = jwt.verify(token, process.env.JWT_SECRET);

        const { data: user, error } = await supabase
            .from('users')
            .select('id')
            .eq('id', verifiedData.id)
            .single();

        if (error || !user) {
            return res.status(401).json({ error: 'Session invalid. User no longer exists.' });
        }

        res.status(200).json({ authenticated: true });
    } catch (err) {
        res.status(401).json({ error: 'Invalid or expired secure token.' });
    }
});

// 4. LOGOUT ENDPOINT (Clears browser Cookie)
app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('sc_token', {
        httpOnly: true,
        secure: true,
        sameSite: 'None'
    });
    res.status(200).json({ message: 'Logged out cleanly.' });
});
// --- Add this middleware near your other routes ---
// Middleware to protect routes and identify the user
const requireAuth = (req, res, next) => {
    const token = req.cookies.sc_token;
    if (!token) return res.status(401).json({ error: 'Unauthorized. Please log in.' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // Attach user payload (contains id) to request
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Session expired or invalid.' });
    }
};
// ==========================================
// 👤 USER PROFILE API
// ==========================================

// Complete Profile Setup (Bio, Birthday, Color, Timezone)
app.put('/api/users/profile', requireAuth, async (req, res) => {
    const userId = req.user.id;
    let { bio, birth_month, birth_day, custom_color, timezone } = req.body;

    // Sanitize the inputs
    bio = sanitizeInput(bio);

    try {
        const { data, error } = await supabase
            .from('users')
            .update({
                bio: bio,
                birth_month: birth_month,
                birth_day: birth_day,
                custom_color: custom_color,
                timezone: timezone
            })
            .eq('id', userId)
            .select('bio, birth_month, birth_day, custom_color, timezone')
            .single();

        if (error) throw error;

        res.status(200).json({
            message: 'Profile updated successfully',
            profile: data
        });
    } catch (err) {
        console.error("Profile Update Error:", err);
        res.status(500).json({ error: 'Failed to update profile.' });
    }
});
// HEALTH ENDPOINT
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'OK',
        message: 'Server is awake!',
        timestamp: new Date().toISOString()
    });
});




// --- CONTACTS ROUTES ---

// 1. Add a Contact
app.post('/api/contacts/add', requireAuth, async (req, res) => {
    const { friend_chat_id } = req.body;
    const myId = req.user.id;

    try {
        const { data: friend, error: friendError } = await supabase
            .from('users')
            .select('id, username') // ✅ GOOD: Strictly usernames
            .eq('chat_id', req.body.friend_chat_id)
            .single();
        if (friendError || !friend) {
            return res.status(404).json({ error: 'User with that Chat ID not found.' });
        }

        if (friend.id === myId) {
            return res.status(400).json({ error: 'You cannot add yourself.' });
        }

        // Check if contact already exists
        const { data: existingContact } = await supabase
            .from('contacts')
            .select('*')
            .eq('user_id', myId)
            .eq('contact_user_id', friend.id)
            .single();

        if (existingContact) {
            return res.status(400).json({ error: 'User is already in your contacts.' });
        }

        // Insert into contacts (Mutual connection!)
        const { error: insertError } = await supabase
            .from('contacts')
            .insert([
                { user_id: myId, contact_user_id: friend.id },
                { user_id: friend.id, contact_user_id: myId } // This line makes it mutual
            ]);
        if (insertError) throw insertError;
        // Live alert the added user to update their screen instantly
        const friendSocket = activeUsers.get(friend.id);
        if (friendSocket) io.to(friendSocket).emit('contacts_updated');
        res.status(200).json({ message: `${friend.username} added to contacts!`, friend });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error while adding contact.' });
    }
});

// 2. Get All Contacts (⚡ FIX 2: N+1 Query Fix)
app.get('/api/contacts', requireAuth, async (req, res) => {
    const myId = req.user.id;
    try {
        // Step 1: Get the list of contacts
        const { data: contacts, error } = await supabase
            .from('contacts')
            .select(`
                is_favorite,
                users!contacts_contact_user_id_fkey (id, username, chat_id)
            `)
            .eq('user_id', myId);

        if (error) throw error;
        const baseContacts = (contacts || []).filter(c => c.users !== null);

        // Step 2: Fetch the last message for each contact in parallel ON THE SERVER.
        // This solves the frontend N+1 problem by handling the load directly next to the DB.
        const contactsWithMessages = await Promise.all(baseContacts.map(async (c) => {
            const friendId = c.users.id;
            const { data: msgs } = await supabase
                .from('messages')
                .select('message_text, sender_id')
                .or(`and(sender_id.eq.${myId},receiver_id.eq.${friendId}),and(sender_id.eq.${friendId},receiver_id.eq.${myId})`)
                .order('created_at', { ascending: false })
                .limit(1); // Only grab the very last message

            const lastMsg = msgs && msgs.length > 0 ? msgs[0] : null;

            return {
                ...c.users,
                is_favorite: c.is_favorite,
                last_message: lastMsg ? lastMsg.message_text : "No messages yet",
                last_message_sender_id: lastMsg ? lastMsg.sender_id : null
            };
        }));

        res.status(200).json({ contacts: contactsWithMessages });
    } catch (err) {
        console.error("GET Contacts Error:", err);
        res.status(500).json({ error: 'Server error while fetching contacts.' });
    }
});

// 3. Remove Contact (Mutual Deletion - FIX)
app.delete('/api/contacts/:contact_id', requireAuth, async (req, res) => {
    const myId = req.user.id;
    const contactId = req.params.contact_id; // Extracting from URL, not body

    try {
        // Delete the relationship in both directions
        await supabase.from('contacts').delete().match({ user_id: myId, contact_user_id: contactId });
        await supabase.from('contacts').delete().match({ user_id: contactId, contact_user_id: myId });
        const friendSocket = activeUsers.get(contactId);
        if (friendSocket) io.to(friendSocket).emit('contacts_updated');
        res.status(200).json({ message: 'Contact removed successfully.' });
    } catch (err) {
        console.error("DELETE Contact Error:", err);
        res.status(500).json({ error: 'Server error while removing contact.' });
    }
});
// --- BLOCK / UNBLOCK CONTACT ---
app.patch('/api/contacts/:id/block', async (req, res) => {
    const myId = req.cookies.sc_token ? jwt.verify(req.cookies.sc_token, process.env.JWT_SECRET).id : null;
    const contactId = req.params.id;
    const { is_blocked } = req.body;

    if (!myId) return res.status(401).json({ error: "Unauthorized" });

    try {
        const { data, error } = await supabase
            .from('contacts')
            .update({ is_blocked: is_blocked })
            .eq('user_id', myId)
            .eq('contact_user_id', contactId)
            .select()
            .single();

        if (error) throw error;
        res.json({ success: true, contact: data });
    } catch (err) {
        console.error("Block Error:", err);
        res.status(500).json({ error: "Could not update block status." });
    }
});

// --- REMOVE CONTACT ---
app.delete('/api/contacts/:id', async (req, res) => {
    const myId = req.cookies.sc_token ? jwt.verify(req.cookies.sc_token, process.env.JWT_SECRET).id : null;
    const contactId = req.params.id;

    if (!myId) return res.status(401).json({ error: "Unauthorized" });

    try {
        // Delete from my contacts
        const { error: err1 } = await supabase
            .from('contacts')
            .delete()
            .eq('user_id', myId)
            .eq('contact_user_id', contactId);
            
        if (err1) throw err1;

        res.json({ success: true, message: "Contact removed" });
    } catch (err) {
        console.error("Remove Error:", err);
        res.status(500).json({ error: "Could not remove contact." });
    }
});
// 4. Toggle Favorite
app.patch('/api/contacts/favorite', requireAuth, async (req, res) => {
    const myId = req.user.id;
    const { contact_id, is_favorite } = req.body;

    try {
        // Only update MY connection to them, don't force them to favorite me!
        const { error } = await supabase
            .from('contacts')
            .update({ is_favorite: is_favorite })
            .match({ user_id: myId, contact_user_id: contact_id });

        if (error) throw error;
        res.status(200).json({ message: 'Favorites updated.' });
    } catch (err) {
        console.error("PATCH Favorite Error:", err);
        res.status(500).json({ error: 'Server error updating favorites.' });
    }
});

// ==========================================
// 💬 MESSAGES API
// ==========================================

// 1. Get Chat History with a specific user
app.get('/api/messages/:contactId', requireAuth, async (req, res) => {
    const myId = req.user.id;
    const contactId = req.params.contactId;

    try {
        // Fetch messages where I am sender & they are receiver, OR they are sender & I am receiver
        const { data: messages, error } = await supabase
            .from('messages')
            .select('*')
            .or(`and(sender_id.eq.${myId},receiver_id.eq.${contactId}),and(sender_id.eq.${contactId},receiver_id.eq.${myId})`)
            .order('created_at', { ascending: true }); // Oldest to newest

        if (error) throw error;
        res.status(200).json(messages);
    } catch (err) {
        console.error("Fetch Messages Error:", err);
        res.status(500).json({ error: 'Failed to load messages.' });
    }
});

// 2. Send a Message (With Optional Image Attachment)
app.post('/api/messages', messageLimiter, requireAuth, (req, res, next) => {
    // Catch multer errors gracefully
    upload.single('attachment')(req, res, (err) => {
        if (err) return res.status(400).json({ error: err.message });
        next();
    });
}, async (req, res) => {
    const myId = req.user.id;
    const { receiver_id, message_text } = req.body;

    if (!receiver_id) {
        return res.status(400).json({ error: "Missing receiver." });
    }

    // Require either text or an image
    if (!message_text && !req.file) {
        return res.status(400).json({ error: "Message text or an image is required." });
    }

    if (message_text && message_text.length > 2000) {
        return res.status(400).json({ error: "Message exceeds the 2,000 character limit." });
    }

    // req.file.path holds the securely generated Cloudinary URL
    const attachmentUrl = req.file ? req.file.path : null;

    try {
        // Save to Database
        const { data: newMessage, error } = await supabase
            .from('messages')
            .insert([{
                sender_id: myId,
                receiver_id: receiver_id,
                message_text: message_text || "", // Fallback to empty string if image-only
                attachment_url: attachmentUrl,
                is_read: false
            }])
            .select()
            .single();

        if (error) throw error;

        // 🚀 LIVE EMISSION: Emit the message instantly via WebSockets!
        const receiverSocketId = activeUsers.get(receiver_id);
        if (receiverSocketId) {
            io.to(receiverSocketId).emit('receive_message', newMessage);
        }

        res.status(201).json(newMessage);
    } catch (err) {
        console.error("Message Send Error:", err);
        res.status(500).json({ error: 'Failed to send message.' });
    }
});


server.listen(PORT, () => {
    console.log(`Server running smoothly on port ${PORT}`);
});
