import express from "express";
import mongoose from "mongoose";
import cors from "cors";

// ---------------------------------------------
// SERVER INIT
// ---------------------------------------------
const app = express();
app.use(cors());
app.use(express.json());

mongoose
  .connect("mongodb://127.0.0.1:27017/sopdb")
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

// ---------------------------------------------
// ROUTES
// ---------------------------------------------

// ➤ GET all SOPs
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
app.listen(5000, () => console.log("Server running on port 5000"));
