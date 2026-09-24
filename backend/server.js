const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
require("dotenv").config();

const app = express();

app.use(cors({ origin: process.env.FRONTEND_URL || "*" }));
app.use(express.json());

// --- SCHEMAS ---
const ServiceSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true }
});
const Service = mongoose.model("Service", ServiceSchema);

const ReservationSchema = new mongoose.Schema({
  clientName: { type: String, required: true },
  contactNumber: { type: String, required: true },
  service: { type: String, required: true },
  appointmentDate: { type: String, required: true },
  status: { type: String, default: "Pending" }
}, { timestamps: true });
const Reservation = mongoose.model("Reservation", ReservationSchema);

// --- ENDPOINTS ---
app.get("/", (req, res) => {
  res.json({ message: "Bellissima Lounge API running" });
});

app.get("/api/reservations", async (req, res) => {
  try {
    const reservations = await Reservation.find();
    res.json(reservations);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/reservations", async (req, res) => {
  try {
    const newReservation = new Reservation(req.body);
    const saved = await newReservation.save();
    res.status(201).json(saved);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete("/api/reservations/:id", async (req, res) => {
  try {
    await Reservation.findByIdAndDelete(req.params.id);
    res.json({ message: "Deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- SERVER START & DB CONNECTION ---
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

if (process.env.MONGODB_URI) {
  mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log("MongoDB connected successfully."))
    .catch((err) => console.error("MongoDB Connection Failed:", err.message));
} else {
  console.error("MONGODB_URI is missing in environment variables.");
}