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

// 2. User Schema (Role, Approval, IELTS, Phone, Fees & Block/Due Date)
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phone: { type: String, default: "" },              // WhatsApp CRM contact
  role: { type: String, default: "student" },        // "admin" kiva "student"
  isApproved: { type: Boolean, default: false },     // General app login access
  hasIeltsAccess: { type: Boolean, default: false }, // Exclusive IELTS access
  feesPaid: { type: Boolean, default: false },       // Fees Status (Paid / Pending)
  feeDueDate: { type: Date, default: null },         // 2nd Installment Due Date
  isBlocked: { type: Boolean, default: false },      // Temporary Account Suspension
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);

// 3. Register Route
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Email already registered." });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({
      name,
      email,
      phone: phone || "",
      password: hashedPassword,
      role: "student",
      isApproved: false,
      hasIeltsAccess: false,
      feesPaid: false,
      isBlocked: false,
      feeDueDate: null
    });

    await newUser.save();
    res.status(201).json({ 
      message: "Account created! Access will be activated upon admin approval." 
    });
  } catch (error) {
    res.status(500).json({ error: "Registration failed: " + error.message });
  }
});

// 4. Login Route (With Approval & Block Checks)
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

    // 1. Check Approval
    if (user.role !== "admin" && !user.isApproved) {
      return res.status(403).json({ 
        error: "Your account is pending verification by EngVerse Admin. Please contact admin for activation." 
      });
    }

    // 2. Check Temporary Block (Fees Dues)
    if (user.role !== "admin" && user.isBlocked) {
      return res.status(403).json({ 
        error: "Your account has been temporarily suspended due to pending installment dues. Kindly clear the fees to restore access." 
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
        phone: user.phone,
        role: user.role,
        isApproved: user.isApproved,
        hasIeltsAccess: user.hasIeltsAccess,
        feesPaid: user.feesPaid,
        feeDueDate: user.feeDueDate,
        isBlocked: user.isBlocked
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

// 8. Toggle Fees Status (Paid / Pending)
app.post("/api/admin/toggle-fees", verifyAdmin, async (req, res) => {
  try {
    const { userId } = req.body;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    user.feesPaid = !user.feesPaid;
    // जर फी पूर्ण भरली असेल तर आपोआप अनब्लॉक करा
    if (user.feesPaid) {
      user.isBlocked = false;
    }
    await user.save();

    res.json({ success: true, feesPaid: user.feesPaid, isBlocked: user.isBlocked });
  } catch (err) {
    res.status(500).json({ error: "Failed to update fees status: " + err.message });
  }
});

// 9. Toggle Temporary Block Status
app.post("/api/admin/toggle-block", verifyAdmin, async (req, res) => {
  try {
    const { userId } = req.body;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    user.isBlocked = !user.isBlocked;
    await user.save();

    res.json({ success: true, isBlocked: user.isBlocked });
  } catch (err) {
    res.status(500).json({ error: "Failed to toggle block status: " + err.message });
  }
});

// 10. Update 2nd Installment Due Date
app.post("/api/admin/update-due-date", verifyAdmin, async (req, res) => {
  try {
    const { userId, feeDueDate } = req.body;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    user.feeDueDate = feeDueDate ? new Date(feeDueDate) : null;
    await user.save();

    res.json({ success: true, message: "Due date updated successfully", feeDueDate: user.feeDueDate });
  } catch (err) {
    res.status(500).json({ error: "Failed to update due date: " + err.message });
  }
});

// 11. Update Student Phone (CRM)
app.post("/api/admin/update-phone", verifyAdmin, async (req, res) => {
  try {
    const { userId, phone } = req.body;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    user.phone = phone;
    await user.save();

    res.json({ success: true, message: "Phone updated successfully", phone: user.phone });
  } catch (err) {
    res.status(500).json({ error: "Failed to update phone: " + err.message });
  }
});

// 12. Delete Student Permanently
app.delete("/api/admin/user/:userId", verifyAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    await User.findByIdAndDelete(userId);
    res.json({ success: true, message: "Student deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete student: " + err.message });
  }
});

app.get("/", (req, res) => {
  res.send("EngVerse Backend with Complete CRM & Automation is Live!");
});

// Quick One-Click Admin Setup Route
app.get("/make-me-admin", async (req, res) => {
  try {
    const adminEmail = "engverse36@gmail.com";
    const user = await User.findOneAndUpdate(
      { email: adminEmail },
      { role: "admin", isApproved: true },
      { new: true }
    );
    if (!user) {
      return res.send(`User ${adminEmail} sapadla nahi. Aadhi ya email ne Signup kara!`);
    }
    res.send(`🎉 Mubarak! ${adminEmail} aata official ADMIN aani APPROVED jhala ahe!`);
  } catch (err) {
    res.send("Error: " + err.message);
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
