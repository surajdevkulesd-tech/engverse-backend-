const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middlewares
app.use(cors());
app.use(express.json({ limit: '25mb' }));

// ==========================================
// 1. MONGODB ATLAS CONNECTION
// ==========================================
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'EngVerseSecretKey2026';

if (MONGO_URI) {
  mongoose.connect(MONGO_URI)
    .then(() => console.log('MongoDB Atlas Connected Successfully!'))
    .catch((err) => console.error('MongoDB Connection Error:', err));
} else {
  console.log('WARNING: MONGO_URI environment variable not found in Render!');
}

// ==========================================
// 2. USER DATABASE SCHEMA (Student/User Profile)
// ==========================================
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  role: {
    type: String,
    default: 'student'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const User = mongoose.model('User', userSchema);

// ==========================================
// 3. AUTHENTICATION APIS (Signup & Login)
// ==========================================

// Navin account banavnyasathi (Register)
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email and password are required.' });
    }

    // Email adhich register ahe ka check karne
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'This email is already registered.' });
    }

    // Password सुरक्षित (hash) karne
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Navin user database madhe save karne
    const newUser = new User({
      name,
      email,
      password: hashedPassword
    });

    await newUser.save();
    return res.status(201).json({ message: 'Account created successfully!' });
  } catch (error) {
    console.error('Registration Error:', error);
    return res.status(500).json({ error: 'Registration failed: ' + error.message });
  }
});

// Login karnyasathi (Login & JWT Token)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    // User shodhane
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid email or password.' });
    }

    // Password barobar ahe ka check karne
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid email or password.' });
    }

    // Login sathi Token generate karne
    const token = jwt.sign(
      { id: user._id, email: user.email, name: user.name, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.json({
      message: 'Login successful!',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login Error:', error);
    return res.status(500).json({ error: 'Login failed: ' + error.message });
  }
});

// ==========================================
// 4. TUMCHA JUNA CODE (Health & Gemini API)
// ==========================================

app.get('/api/health', (req, res) => {
  res.json({
    status: 'UP',
    application: 'EngVerse IELTS Evaluation Engine',
    version: '1.0.0'
  });
});

app.post('/api/gemini', async (req, res) => {
  try {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ error: 'Server configuration error: GEMINI_API_KEY missing.' });
    }

    const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`;

    const apiResponse = await fetch(geminiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body)
    });

    const data = await apiResponse.json();
    return res.status(apiResponse.status).json(data);
  } catch (error) {
    console.error('Gemini Backend Error:', error);
    return res.status(500).json({ error: 'Internal server error processing evaluation.' });
  }
});

// ==========================================
// 5. SERVER START
// ==========================================
app.listen(PORT, () => {
  console.log(`EngVerse Server is running on port ${PORT}`);
});
