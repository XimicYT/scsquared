const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'); // 🌟 Added JWT
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// Initialize Supabase Client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

app.use(cors());
app.use(express.json());

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

        if (!data) return randomId; // ID is unique and available
        attempts++;
    }
    throw new Error('Failed to generate a unique Chat ID');
}

// 1. REGISTER ENDPOINT
app.post('/api/auth/register', async (req, res) => {
    const { first_name, username, email, password } = req.body;

    if (!username || !password || !first_name || !email) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    try {
        const passwordHash = await bcrypt.hash(password, 10);
        const chatId = await generateUniqueChatId();

        const { data, error } = await supabase
            .from('users')
            .insert([{
                first_name: first_name,
                username: username, // Display Name
                email: email,
                password_hash: passwordHash,
                chat_id: chatId
            }])
            .select('id, username, chat_id, first_name')
            .single();

        if (error) {
            if (error.code === '23505') {
                throw new Error("That email or display name is already taken.");
            }
            throw error;
        }
        res.status(201).json({ message: 'User registered successfully', user: data });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. LOGIN ENDPOINT (Generates JWT)
app.post('/api/auth/login', async (req, res) => {
    const { login_identifier, password } = req.body;

    if (!login_identifier || !password) {
        return res.status(400).json({ error: 'Please enter your tag or display name, and password.' });
    }

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

        // 🌟 Create the secure token! (Valid for 24 hours)
        const token = jwt.sign(
            { id: user.id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(200).json({
            message: 'Login successful',
            user: { 
                id: user.id, 
                username: user.username, 
                chat_id: user.chat_id, 
                first_name: user.first_name,
                token: token // Send token to frontend
            }
        });
    } catch (err) {
        res.status(401).json({ error: err.message });
    }
});

// 3. SECURE VERIFICATION ENDPOINT
app.get('/api/auth/verify', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1]; // Extract token from "Bearer <TOKEN>"

        if (!token) {
            return res.status(401).json({ error: 'Access denied. No token provided.' });
        }

        // Verify the token using your Render environment secret
        const verifiedData = jwt.verify(token, process.env.JWT_SECRET);

        // Security check: Ensure the user still exists in Supabase
        const { data: user, error } = await supabase
            .from('users')
            .select('id')
            .eq('id', verifiedData.id)
            .single();

        if (error || !user) {
            return res.status(401).json({ error: 'Session invalid. User no longer exists.' });
        }

        // Token is valid!
        res.status(200).json({ authenticated: true });
    } catch (err) {
        res.status(401).json({ error: 'Invalid or expired secure token.' });
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

app.listen(PORT, () => {
    console.log(`Server running smoothly on port ${PORT}`);
});
