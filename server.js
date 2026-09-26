require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

// 1. MongoDB Connection
const MONGO_URI = process.env.MONGO_URI;
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("MongoDB Connected Successfully"))
  .catch((err) => console.error("MongoDB Connection Error:", err.message));

// 2. User Schema (Approval & IELTS access sobat)
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isApproved: { type: Boolean, default: false },     // General app login access
  hasIeltsAccess: { type: Boolean, default: false }, // Exclusive IELTS access
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);

// 3. Register Route
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Email already registered." });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      isApproved: false,     // By default pending rahil
      hasIeltsAccess: false  // By default IELTS locked rahil
    });

    await newUser.save();
    res.status(201).json({ 
      message: "Account created! Access will be activated upon admin approval." 
    });
  } catch (error) {
    res.status(500).json({ error: "Registration failed: " + error.message });
  }
});

// 4. Login Route
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "Invalid email or password." });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid email or password." });
    }

    // CHECK: Admin ne approve kela ahe ka
    if (!user.isApproved) {
      return res.status(403).json({ 
        error: "Your account is pending verification by EngVerse Admin. Please contact admin for activation." 
      });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || "engverse_secret_key",
      { expiresIn: "7d" }
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        isApproved: user.isApproved,
        hasIeltsAccess: user.hasIeltsAccess
      }
    });
  } catch (error) {
    res.status(500).json({ error: "Login failed: " + error.message });
  }
});

// 5. Root test route
app.get("/", (req, res) => {
  res.send("EngVerse Backend is Running Live!");
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
