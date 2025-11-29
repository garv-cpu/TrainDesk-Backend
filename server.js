import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import cron from "node-cron";
import fetch from "node-fetch";

dotenv.config();

// ---------------------------------------------
// SERVER INIT
// ---------------------------------------------
const app = express();
app.use(cors());
app.use(express.json());

// ---------------------------------------------
// CONNECT MONGODB
// ---------------------------------------------
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.log("MongoDB Error:", err));

// ---------------------------------------------
// MONGODB MODEL
// ---------------------------------------------
const SOPSchema = new mongoose.Schema({
  title: { type: String, required: true },
  dept: { type: String, required: true },
  content: { type: String, required: true },
  updated: { type: Date, default: Date.now },
});

const SOP = mongoose.model("SOP", SOPSchema);

// --------------------------------------------------
// KEEP-ALIVE ENDPOINT (important for cron job)
// --------------------------------------------------
app.get("/ping", (req, res) => {
  res.json({ status: "active", time: new Date() });
});

// --------------------------------------------------
// CRON JOB - KEEP RENDER BACKEND AWAKE
// --------------------------------------------------
// Runs every 14 minutes
cron.schedule("*/14 * * * *", async () => {
  try {
    console.log("🟢 Keep-alive ping executed");
    await fetch(process.env.SERVER_URL + "/ping");
  } catch (err) {
    console.log("Ping error:", err);
  }
});

// ---------------------------------------------
// ROUTES
// ---------------------------------------------

// ➤ GET all SOPs

// ➤ GET DASHBOARD STATS
app.get("/api/stats", async (req, res) => {
  try {
    const totalSOPs = await SOP.countDocuments();

    // Additional models later:
    const totalEmployees = 42; 
    const activeTrainings = 12;
    const completedTrainings = 89;

    res.json({
      employees: totalEmployees,
      activeTrainings,
      completedTrainings,
      pendingSOPs: totalSOPs
    });

  } catch (err) {
    res.status(500).json({ message: "Failed to fetch stats" });
  }
});

app.get("/api/sops", async (req, res) => {
  try {
    const sops = await SOP.find().sort({ updated: -1 });
    res.json(sops);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch SOPs" });
  }
});

// ➤ GET one SOP
app.get("/api/sops/:id", async (req, res) => {
  try {
    const sop = await SOP.findById(req.params.id);
    if (!sop) return res.status(404).json({ message: "SOP not found" });
    res.json(sop);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch SOP" });
  }
});

// ➤ CREATE SOP
app.post("/api/sops", async (req, res) => {
  try {
    const sop = new SOP(req.body);
    await sop.save();
    res.json({ message: "SOP Created Successfully", sop });
  } catch (err) {
    res.status(500).json({ message: "Failed to create SOP" });
  }
});

// ➤ UPDATE SOP
app.put("/api/sops/:id", async (req, res) => {
  try {
    const updated = await SOP.findByIdAndUpdate(
      req.params.id,
      { ...req.body, updated: Date.now() },
      { new: true }
    );

    if (!updated) return res.status(404).json({ message: "SOP not found" });
    res.json({ message: "SOP Updated", updated });
  } catch (err) {
    res.status(500).json({ message: "Failed to update SOP" });
  }
});

// ➤ DELETE SOP
app.delete("/api/sops/:id", async (req, res) => {
  try {
    await SOP.findByIdAndDelete(req.params.id);
    res.json({ message: "SOP Deleted" });
  } catch (err) {
    res.status(500).json({ message: "Failed to delete SOP" });
  }
});

// ---------------------------------------------
// START SERVER
// ---------------------------------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
