const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();

app.use(cors({ origin: process.env.FRONTEND_URL || "*" }));
app.use(express.json());

// --- SCHEMAS ---
const ReservationSchema = new mongoose.Schema({
  clientId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  clientName: { type: String, required: true },
  contactNumber: { type: String, required: true },
  service: { type: String, required: true },
  appointmentDate: { type: String, required: true },
  status: { type: String, default: "Pending" }
}, { timestamps: true });
const Reservation = mongoose.model("Reservation", ReservationSchema);

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["admin", "client"], default: "client" },
  status: { type: String, enum: ["active", "suspended"], default: "active" }
}, { timestamps: true });
const User = mongoose.model("User", UserSchema);

const InventorySchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  category: { type: String, required: true, trim: true },
  quantity: { type: Number, required: true, min: 0 },
  unit: { type: String, required: true, trim: true },
  reorderLevel: { type: Number, required: true, min: 0, default: 5 },
  cost: { type: Number, min: 0, default: 0 },
  updatedBy: { type: String }
}, { timestamps: true });
const Inventory = mongoose.model("Inventory", InventorySchema);

const JWT_SECRET = process.env.JWT_SECRET || "bellissima-development-secret";

function createToken(user) {
  return jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: "8h" });
}

function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ message: "Authentication required." });

  try {
    req.auth = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ message: "Your session has expired." });
  }
}

function requireAdmin(req, res, next) {
  if (req.auth.role !== "admin") return res.status(403).json({ message: "Admin access required." });
  next();
}

// --- ENDPOINTS ---
app.get("/", (req, res) => {
  res.json({ message: "Bellissima Lounge API running" });
});

app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: "Name, email, and password are required." });
    if (password.length < 6) return res.status(400).json({ message: "Password must be at least 6 characters." });
    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) return res.status(409).json({ message: "An account with that email already exists." });

    const user = await User.create({ name, email, password: await bcrypt.hash(password, 10), role: "client" });
    res.status(201).json({ message: "Client account created. You can now sign in." });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email?.toLowerCase() });
    if (!user || !(await bcrypt.compare(req.body.password || "", user.password))) {
      return res.status(401).json({ message: "Incorrect email or password." });
    }
    if (user.status !== "active") return res.status(403).json({ message: "This account is currently suspended." });
    res.json({ token: createToken(user), user: { name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    res.status(500).json({ message: "Unable to sign in right now." });
  }
});

app.get("/api/profile", requireAuth, async (req, res) => {
  const user = await User.findById(req.auth.id).select("name email role status");
  if (!user) return res.status(404).json({ message: "User not found." });
  res.json({ user });
});

app.get("/api/inventory", requireAuth, async (req, res) => {
  try {
    const inventory = await Inventory.find().sort({ category: 1, name: 1 });
    res.json(inventory);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post("/api/inventory", requireAuth, requireAdmin, async (req, res) => {
  try {
    const item = await Inventory.create({ ...req.body, updatedBy: req.auth.id });
    res.status(201).json(item);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.put("/api/inventory/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const item = await Inventory.findByIdAndUpdate(req.params.id, { ...req.body, updatedBy: req.auth.id }, { new: true, runValidators: true });
    if (!item) return res.status(404).json({ message: "Inventory item not found." });
    res.json(item);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.delete("/api/inventory/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    await Inventory.findByIdAndDelete(req.params.id);
    res.json({ message: "Inventory item removed." });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/api/reservations", requireAuth, async (req, res) => {
  try {
    const query = req.auth.role === "admin" ? {} : { clientId: req.auth.id };
    const reservations = await Reservation.find(query).sort({ appointmentDate: 1 });
    res.json(reservations);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/reservations", requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.auth.id).select("name");
    if (!user) return res.status(404).json({ error: "User not found." });
    const newReservation = new Reservation({ ...req.body, clientId: user._id, clientName: user.name });
    const saved = await newReservation.save();
    res.status(201).json(saved);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete("/api/reservations/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    await Reservation.findByIdAndDelete(req.params.id);
    res.json({ message: "Deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- SERVER START & DB CONNECTION ---
const PORT = process.env.PORT || 5000;

async function startServer() {
  if (!process.env.MONGODB_URI) {
    console.error("MONGODB_URI is missing in environment variables.");
    process.exit(1);
  }

  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log("MongoDB connected successfully.");
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (err) {
    console.error("MongoDB Connection Failed:", err.message);
    process.exit(1);
  }
}

startServer();