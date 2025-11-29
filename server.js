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

// ---------------------------------------------
// EMPLOYEE MODEL
// ---------------------------------------------
const EmployeeSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  dept: { type: String, required: true },
  role: { type: String, enum: ["owner", "manager", "staff"], default: "staff" },
  status: { type: String, enum: ["active", "inactive"], default: "active" },
  createdAt: { type: Date, default: Date.now },
});

const Employee = mongoose.model("Employee", EmployeeSchema);

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
app.get("/api/employees", async (req, res) => {
  try {
    const employees = await Employee.find().sort({ createdAt: -1 });
    res.json(employees);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch employees" });
  }
});

app.get("/api/employees/:id", async (req, res) => {
  try {
    const emp = await Employee.findById(req.params.id);
    if (!emp) return res.status(404).json({ message: "Employee not found" });
    res.json(emp);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch employee" });
  }
});

app.post("/api/employees", async (req, res) => {
  try {
    const employee = new Employee(req.body);
    await employee.save();
    res.json({ message: "Employee Added", employee });
  } catch (err) {

    if (err.code === 11000) {
      // Duplicate email error
      return res.status(400).json({ message: "Email already exists" });
    }

    res.status(500).json({ message: "Failed to create employee" });
  }
});


app.put("/api/employees/:id", async (req, res) => {
  try {
    const updated = await Employee.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );
    if (!updated) return res.status(404).json({ message: "Employee not found" });
    res.json({ message: "Employee Updated", updated });
  } catch (err) {
    res.status(500).json({ message: "Failed to update employee" });
  }
});

app.delete("/api/employees/:id", async (req, res) => {
  try {
    await Employee.findByIdAndDelete(req.params.id);
    res.json({ message: "Employee Deleted" });
  } catch (err) {
    res.status(500).json({ message: "Failed to delete employee" });
  }
});

// ➤ GET DASHBOARD STATS
app.get("/api/stats", async (req, res) => {
  try {
    const totalEmployees = await Employee.countDocuments();
    const totalSOPs = await SOP.countDocuments();

    // For now static → will replace later with real training module
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
