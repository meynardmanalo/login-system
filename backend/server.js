const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const cors = require("cors");
require("dotenv").config();

const app = express();

app.use(cors({
  origin: process.env.FRONTEND_URL || "*"
}));
app.use(express.json());

/* ---------------------------------------------------------
   SCHEMAS  (Normalized to 3NF)
--------------------------------------------------------- */

// USERS
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  status: { type: String, enum: ["active", "suspended"], default: "active" }
}, { timestamps: { createdAt: "createdAt", updatedAt: false } });

const User = mongoose.model("User", userSchema);

// ROLES (lookup table)
const roleSchema = new mongoose.Schema({
  role_name: { type: String, required: true, unique: true },
  description: { type: String }
});

const Role = mongoose.model("Role", roleSchema);

// USER_ROLES (junction table: many-to-many between Users and Roles)
const userRoleSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  role: { type: mongoose.Schema.Types.ObjectId, ref: "Role", required: true },
  assignedAt: { type: Date, default: Date.now }
});
userRoleSchema.index({ user: 1, role: 1 }, { unique: true }); // composite key

const UserRole = mongoose.model("UserRole", userRoleSchema);

// SESSIONS (one user -> many sessions)
const sessionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  sessionToken: { type: String, required: true },
  ipAddress: { type: String },
  userAgent: { type: String },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true }
});

const Session = mongoose.model("Session", sessionSchema);

// AUTH_TOKENS (one user -> many tokens; OTP / password reset)
const authTokenSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  tokenCode: { type: String, required: true },
  type: { type: String, enum: ["password_reset", "email_otp"], required: true },
  expiresAt: { type: Date, required: true },
  isUsed: { type: Boolean, default: false }
});

const AuthToken = mongoose.model("AuthToken", authTokenSchema);

/* ---------------------------------------------------------
   SEED DEFAULT ROLES ON STARTUP
--------------------------------------------------------- */
async function seedRoles() {
  const defaults = [
    { role_name: "Admin", description: "Full system access" },
    { role_name: "Standard User", description: "Regular login-system user" },
    { role_name: "Guest", description: "Limited, read-only access" }
  ];
  for (const r of defaults) {
    await Role.updateOne({ role_name: r.role_name }, { $setOnInsert: r }, { upsert: true });
  }
}

/* ---------------------------------------------------------
   ROUTES
--------------------------------------------------------- */

app.get("/", (req, res) => {
  res.json({ message: "Login API is running." });
});

// REGISTER
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required." });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters." });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "Email is already registered." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      name,
      email,
      password: hashedPassword
    });

    // Assign default role via the UserRole junction table
    const defaultRole = await Role.findOne({ role_name: "Standard User" });
    if (defaultRole) {
      await UserRole.create({ user: newUser._id, role: defaultRole._id });
    }

    res.status(201).json({ message: "Registration successful." });
  } catch (error) {
    res.status(500).json({ message: "Server error." });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password." });
    }
    if (user.status === "suspended") {
      return res.status(403).json({ message: "This account has been suspended." });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const token = jwt.sign(
      { userId: user._id, name: user.name, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    // Log this login as a Session record
    await Session.create({
      user: user._id,
      sessionToken: token,
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"] || "unknown",
      expiresAt: new Date(Date.now() + 60 * 60 * 1000) // 1 hour, matches JWT expiry
    });

    res.json({
      message: "Login successful.",
      token,
      user: {
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    res.status(500).json({ message: "Server error." });
  }
});

// LOGOUT — invalidate the current session
app.post("/api/logout", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized." });
    }
    const token = authHeader.split(" ")[1];
    await Session.deleteOne({ sessionToken: token });
    res.json({ message: "Logged out." });
  } catch (error) {
    res.status(500).json({ message: "Server error." });
  }
});

// PROFILE — now also returns the user's role
app.get("/api/profile", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized." });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const userRole = await UserRole.findOne({ user: decoded.userId }).populate("role");

    res.json({
      message: "Protected data.",
      user: {
        name: decoded.name,
        email: decoded.email,
        role: userRole ? userRole.role.role_name : "Standard User"
      }
    });
  } catch (error) {
    res.status(401).json({ message: "Invalid or expired token." });
  }
});

// FORGOT PASSWORD — creates an AuthToken (email sending not wired up yet)
app.post("/api/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      // Respond the same way whether or not the email exists (avoids leaking which emails are registered)
      return res.json({ message: "If that email is registered, a reset code has been generated." });
    }

    const tokenCode = crypto.randomInt(100000, 999999).toString(); // 6-digit OTP
    await AuthToken.create({
      user: user._id,
      tokenCode,
      type: "password_reset",
      expiresAt: new Date(Date.now() + 15 * 60 * 1000) // 15 minutes
    });

    console.log(`Password reset code for ${email}: ${tokenCode}`); // placeholder until email sending is added

    res.json({ message: "If that email is registered, a reset code has been generated." });
  } catch (error) {
    res.status(500).json({ message: "Server error." });
  }
});

// RESET PASSWORD — verifies the AuthToken then updates the password
app.post("/api/reset-password", async (req, res) => {
  try {
    const { email, tokenCode, newPassword } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid request." });
    }

    const authToken = await AuthToken.findOne({
      user: user._id,
      tokenCode,
      type: "password_reset",
      isUsed: false,
      expiresAt: { $gt: new Date() }
    });

    if (!authToken) {
      return res.status(400).json({ message: "Invalid or expired code." });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    authToken.isUsed = true;
    await authToken.save();

    res.json({ message: "Password reset successful." });
  } catch (error) {
    res.status(500).json({ message: "Server error." });
  }
});

const PORT = process.env.PORT || 5000;
mongoose.connect(process.env.MONGODB_URI)
  .then(async () => {
    console.log("MongoDB connected.");
    await seedRoles();
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error("MongoDB connection failed:", error);
  });