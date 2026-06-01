const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'); 
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

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
app.post('/api/auth/register', async (req, res) => {
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
            user: data 
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. LOGIN ENDPOINT (Generates secure HttpOnly Cookie)
app.post('/api/auth/login', async (req, res) => {
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
                first_name: user.first_name
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

// HEALTH ENDPOINT
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'OK',
        message: 'Server is awake!',
        timestamp: new Date().toISOString()
    });
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

// --- CONTACTS ROUTES ---

// 1. Add a Contact
app.post('/api/contacts/add', requireAuth, async (req, res) => {
    const { friend_chat_id } = req.body;
    const myId = req.user.id;

    try {
        // Find the user they are trying to add
        const { data: friend, error: friendError } = await supabase
            .from('users')
            .select('id, username, first_name')
            .eq('chat_id', friend_chat_id)
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

        res.status(200).json({ message: `${friend.first_name} added to contacts!`, friend });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error while adding contact.' });
    }
});

// 2. Get All Contacts
app.get('/api/contacts', requireAuth, async (req, res) => {
    const myId = req.user.id;

    try {
        // Fetch contacts and join with the users table to get their details
        // Note: This assumes you have a foreign key set up on contact_user_id -> users(id)
        const { data: contacts, error } = await supabase
            .from('contacts')
            .select(`
                contact_user_id,
                users!contact_user_id (id, first_name, username, chat_id)
            `)
            .eq('user_id', myId);

        if (error) throw error;

        // Flatten the data structure slightly for the frontend
        const formattedContacts = contacts.map(c => c.users);

        res.status(200).json({ contacts: formattedContacts });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch contacts.' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running smoothly on port ${PORT}`);
});
