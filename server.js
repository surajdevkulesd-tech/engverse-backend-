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

// 2. User Schema (Role, Approval aani IELTS Flags sobat)
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: "student" },        // "admin" kiva "student"
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
      role: "student",
      isApproved: false,
      hasIeltsAccess: false
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

    // Jar user student asel aani approve nasel tar block kara
    if (user.role !== "admin" && !user.isApproved) {
      return res.status(403).json({ 
        error: "Your account is pending verification by EngVerse Admin. Please contact admin for activation." 
      });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
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
        role: user.role,
        isApproved: user.isApproved,
        hasIeltsAccess: user.hasIeltsAccess
      }
    });
  } catch (error) {
    res.status(500).json({ error: "Login failed: " + error.message });
  }
});

// --- ADMIN APIS ---

// Middleware: Admin check
const verifyAdmin = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Access denied. Token missing." });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "engverse_secret_key");
    if (decoded.role !== "admin") {
      return res.status(403).json({ error: "Access denied. Admin rights required." });
    }
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token." });
  }
};

// 5. Get All Users List (Admin Only)
app.get("/api/admin/users", verifyAdmin, async (req, res) => {
  try {
    const users = await User.find({ role: "student" }).sort({ createdAt: -1 });
    res.json({ success: true, users });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch users: " + err.message });
  }
});

// 6. Toggle Student Approval (Approve / Revoke)
app.post("/api/admin/toggle-approve", verifyAdmin, async (req, res) => {
  try {
    const { userId } = req.body;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    user.isApproved = !user.isApproved;
    await user.save();

    res.json({ success: true, isApproved: user.isApproved });
  } catch (err) {
    res.status(500).json({ error: "Failed to update approval: " + err.message });
  }
});

// 7. Toggle IELTS Access (Grant / Revoke)
app.post("/api/admin/toggle-ielts", verifyAdmin, async (req, res) => {
  try {
    const { userId } = req.body;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    user.hasIeltsAccess = !user.hasIeltsAccess;
    await user.save();

    res.json({ success: true, hasIeltsAccess: user.hasIeltsAccess });
  } catch (err) {
    res.status(500).json({ error: "Failed to update IELTS access: " + err.message });
  }
});

app.get("/", (req, res) => {
  res.send("EngVerse Backend with Secure Admin Panel is Live!");
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
