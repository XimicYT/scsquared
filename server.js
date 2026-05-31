const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
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

// 1. REGISTER ENDPOINT (UPDATED)
app.post('/api/auth/register', async (req, res) => {
    // We now accept first_name and email alongside the others
    const { first_name, username, email, password } = req.body; 
    
    if (!username || !password || !first_name || !email) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    try {
        const passwordHash = await bcrypt.hash(password, 10);
        const chatId = await generateUniqueChatId();

        // Insert the new fields into Supabase
        const { data, error } = await supabase
            .from('users')
            .insert([{ 
                first_name: first_name, 
                username: username, // This is the Display Name
                email: email,
                password_hash: passwordHash, 
                chat_id: chatId 
            }])
            .select('id, username, chat_id, first_name')
            .single();

        if (error) {
            // Handle duplicate email or username errors cleanly
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

// 2. LOGIN ENDPOINT
app.post('/api/auth/login', async (req, res) => {
    const { chat_id, password } = req.body; // Login via the 6-digit phone-style ID
    if (!chat_id || !password) {
        return res.status(400).json({ error: 'Chat ID and password are required.' });
    }

    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('chat_id', chat_id)
            .single();

        if (error || !user) {
            return res.status(401).json({ error: 'Invalid Chat ID or password.' });
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid Chat ID or password.' });
        }

        res.status(200).json({
            message: 'Login successful',
            user: { id: user.id, username: user.username, chat_id: user.chat_id }
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`Server running smoothly on port ${PORT}`);
});
