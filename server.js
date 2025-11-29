import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import cron from "node-cron";
import fetch from "node-fetch";
import admin from "firebase-admin";

dotenv.config();

// -------------------- Firebase Admin init --------------------
if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
  console.error("Missing FIREBASE_SERVICE_ACCOUNT env var. Exiting.");
  process.exit(1);
}

const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const firestore = admin.firestore();
const firebaseAuth = admin.auth();

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
// MONGODB MODELS (tenant scoped to ownerId)
// ---------------------------------------------
const SOPSchema = new mongoose.Schema({
  ownerId: { type: String, required: true }, // firebase uid of admin
  title: { type: String, required: true },
  dept: { type: String, required: true },
  content: { type: String, required: true },
  updated: { type: Date, default: Date.now },
});

const EmployeeSchema = new mongoose.Schema({
  ownerId: { type: String, required: true }, // admin uid
  firebaseUid: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  email: { type: String, required: true },
  dept: { type: String, required: true },
  role: { type: String, enum: ["owner", "manager", "staff"], default: "staff" },
  status: { type: String, enum: ["active", "inactive"], default: "active" },
  createdAt: { type: Date, default: Date.now },
});

const SOP = mongoose.model("SOP", SOPSchema);
const Employee = mongoose.model("Employee", EmployeeSchema);

// --------------------------------------------------
// KEEP-ALIVE / CRON
// --------------------------------------------------
app.get("/ping", (req, res) => {
  res.json({ status: "active", time: new Date() });
});

// ping every 14 minutes to keep render awake (optional)
if (process.env.SERVER_URL) {
  cron.schedule("*/14 * * * *", async () => {
    try {
      console.log("🟢 Keep-alive ping executed");
      await fetch(process.env.SERVER_URL + "/ping");
    } catch (err) {
      console.log("Ping error:", err);
    }
  });
}

// ---------------------- Middleware ----------------------

// Verify Firebase ID token and attach uid to req.userUid
async function authenticate(req, res, next) {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) return res.status(401).json({ message: "Missing token" });

  const idToken = authHeader.split(" ")[1];
  try {
    const decoded = await firebaseAuth.verifyIdToken(idToken);
    req.userUid = decoded.uid;
    next();
  } catch (err) {
    console.error("Token verify error:", err);
    return res.status(401).json({ message: "Invalid token" });
  }
}

// Require admin role (stored in Firestore collection `users/<uid>` with field role: 'admin')
async function requireAdmin(req, res, next) {
  try {
    const doc = await firestore.doc(`users/${req.userUid}`).get();
    if (!doc.exists) return res.status(403).json({ message: "Role not found" });
    const data = doc.data();
    if (data.role !== "admin") return res.status(403).json({ message: "Admin access required" });
    next();
  } catch (err) {
    console.error("requireAdmin error", err);
    res.status(500).json({ message: "Server error" });
  }
}

// -----------------------------
// ROUTES (protected where needed)
// -----------------------------

// ---------- EMPLOYEES (ADMIN only) ----------
/*
POST /api/employees
  body: { name, email, dept, role, status, password }
  Creates:
   - Firebase user (email+password)
   - Firestore users/<uid> { role: "employee", email }
   - Mongo Employee doc { ownerId, firebaseUid, ... }
*/
app.post("/api/employees", authenticate, requireAdmin, async (req, res) => {
  try {
    const { name, email, dept, role = "staff", status = "active", password } = req.body;
    if (!name || !email || !dept || !password) {
      return res.status(400).json({ message: "Missing required fields (name,email,dept,password)" });
    }

    // 1) create firebase auth user
    const fbUser = await firebaseAuth.createUser({
      email,
      password,
      displayName: name,
    });

    // 2) write to Firestore users/uid to mark role=employee
    await firestore.doc(`users/${fbUser.uid}`).set({
      email,
      role: "employee",
      createdAt: Date.now(),
      ownerId: req.userUid
    });

    // 3) create Mongo Employee linked to ownerId + firebaseUid
    const employee = new Employee({
      ownerId: req.userUid,
      firebaseUid: fbUser.uid,
      name,
      email,
      dept,
      role,
      status
    });
    await employee.save();

    res.json({ message: "Employee Added", employee });
  } catch (err) {
    console.error("POST /api/employees err", err);
    // duplicate firebaseUid or mongo unique errors handled
    if (err.code === 11000) return res.status(400).json({ message: "Employee already exists" });
    return res.status(500).json({ message: "Failed to create employee", error: err.message });
  }
});

// GET all employees for admin (tenant scoped)
app.get("/api/employees", authenticate, requireAdmin, async (req, res) => {
  try {
    const employees = await Employee.find({ ownerId: req.userUid }).sort({ createdAt: -1 });
    res.json(employees);
  } catch (err) {
    console.error("GET /api/employees err", err);
    res.status(500).json({ message: "Failed to fetch employees" });
  }
});

// GET single employee (admin only, must belong to owner)
app.get("/api/employees/:id", authenticate, requireAdmin, async (req, res) => {
  try {
    const emp = await Employee.findById(req.params.id);
    if (!emp || emp.ownerId !== req.userUid) return res.status(404).json({ message: "Employee not found" });
    res.json(emp);
  } catch (err) {
    console.error("GET /api/employees/:id err", err);
    res.status(500).json({ message: "Failed to fetch employee" });
  }
});

// UPDATE employee (admin only)
app.put("/api/employees/:id", authenticate, requireAdmin, async (req, res) => {
  try {
    const emp = await Employee.findById(req.params.id);
    if (!emp || emp.ownerId !== req.userUid) return res.status(404).json({ message: "Employee not found" });

    // Optionally update Firebase user email/displayName if requested
    if (req.body.email || req.body.name) {
      const updates = {};
      if (req.body.email) updates.email = req.body.email;
      if (req.body.name) updates.displayName = req.body.name;
      try {
        await firebaseAuth.updateUser(emp.firebaseUid, updates);
        // update Firestore user doc as well
        await firestore.doc(`users/${emp.firebaseUid}`).update({
          email: req.body.email || emp.email,
        });
      } catch (e) {
        console.warn("Could not update firebase user", e);
      }
    }

    const updated = await Employee.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json({ message: "Employee Updated", updated });
  } catch (err) {
    console.error("PUT /api/employees/:id err", err);
    res.status(500).json({ message: "Failed to update employee" });
  }
});

// DELETE employee (admin only)
app.delete("/api/employees/:id", authenticate, requireAdmin, async (req, res) => {
  try {
    const emp = await Employee.findById(req.params.id);
    if (!emp || emp.ownerId !== req.userUid) return res.status(404).json({ message: "Employee not found" });

    // delete firebase user
    try {
      await firebaseAuth.deleteUser(emp.firebaseUid);
    } catch (e) {
      console.warn("Failed to delete firebase user:", e.message);
    }

    await Employee.findByIdAndDelete(req.params.id);
    // remove Firestore user doc
    await firestore.doc(`users/${emp.firebaseUid}`).delete().catch(()=>{});
    res.json({ message: "Employee Deleted" });
  } catch (err) {
    console.error("DELETE /api/employees/:id err", err);
    res.status(500).json({ message: "Failed to delete employee" });
  }
});

// ---------- SOPs (tenant scoped) ----------

// Create SOP (admin)
app.post("/api/sops", authenticate, requireAdmin, async (req, res) => {
  try {
    const { title, dept, content } = req.body;
    if (!title || !dept || !content) return res.status(400).json({ message: "Missing fields" });

    const sop = new SOP({
      ownerId: req.userUid,
      title, dept, content
    });
    await sop.save();
    res.json({ message: "SOP Created Successfully", sop });
  } catch (err) {
    console.error("POST /api/sops err", err);
    res.status(500).json({ message: "Failed to create SOP" });
  }
});

// GET all SOPs for admin (tenant)
app.get("/api/sops", authenticate, requireAdmin, async (req, res) => {
  try {
    const sops = await SOP.find({ ownerId: req.userUid }).sort({ updated: -1 });
    res.json(sops);
  } catch (err) {
    console.error("GET /api/sops err", err);
    res.status(500).json({ message: "Failed to fetch SOPs" });
  }
});

// GET recent (limit 3)
app.get("/api/sops/recent", authenticate, requireAdmin, async (req, res) => {
  try {
    const sops = await SOP.find({ ownerId: req.userUid }).sort({ updated: -1 }).limit(3);
    res.json(sops);
  } catch (err) {
    console.error("GET /api/sops/recent err", err);
    res.status(500).json({ message: "Failed to fetch recent SOPs" });
  }
});

// GET single SOP
app.get("/api/sops/:id", authenticate, requireAdmin, async (req, res) => {
  try {
    const sop = await SOP.findById(req.params.id);
    if (!sop || sop.ownerId !== req.userUid) return res.status(404).json({ message: "SOP not found" });
    res.json(sop);
  } catch (err) {
    console.error("GET /api/sops/:id err", err);
    res.status(500).json({ message: "Failed to fetch SOP" });
  }
});

// UPDATE SOP
app.put("/api/sops/:id", authenticate, requireAdmin, async (req, res) => {
  try {
    const sop = await SOP.findById(req.params.id);
    if (!sop || sop.ownerId !== req.userUid) return res.status(404).json({ message: "SOP not found" });

    const updated = await SOP.findByIdAndUpdate(req.params.id, { ...req.body, updated: Date.now() }, { new: true });
    res.json({ message: "SOP Updated", updated });
  } catch (err) {
    console.error("PUT /api/sops/:id err", err);
    res.status(500).json({ message: "Failed to update SOP" });
  }
});

// DELETE SOP
app.delete("/api/sops/:id", authenticate, requireAdmin, async (req, res) => {
  try {
    const sop = await SOP.findById(req.params.id);
    if (!sop || sop.ownerId !== req.userUid) return res.status(404).json({ message: "SOP not found" });

    await SOP.findByIdAndDelete(req.params.id);
    res.json({ message: "SOP Deleted" });
  } catch (err) {
    console.error("DELETE /api/sops/:id err", err);
    res.status(500).json({ message: "Failed to delete SOP" });
  }
});

// ---------- STATS (tenant) ----------
app.get("/api/stats", authenticate, requireAdmin, async (req, res) => {
  try {
    const totalEmployees = await Employee.countDocuments({ ownerId: req.userUid });
    const totalSOPs = await SOP.countDocuments({ ownerId: req.userUid });

    // These are placeholders — update when training module exists per tenant
    const activeTrainings = 0;
    const completedTrainings = 0;

    res.json({
      employees: totalEmployees,
      activeTrainings,
      completedTrainings,
      pendingSOPs: totalSOPs
    });
  } catch (err) {
    console.error("GET /api/stats err", err);
    res.status(500).json({ message: "Failed to fetch stats" });
  }
});

// ---------------------------------------------
// START SERVER
// ---------------------------------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
