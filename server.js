import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import cron from "node-cron";
import fetch from "node-fetch";
import admin from "firebase-admin";

dotenv.config();

/* ----------------------------------------------------
   🔥 FIXED FIREBASE ADMIN INITIALIZATION
---------------------------------------------------- */
if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
  console.error("Missing FIREBASE_SERVICE_ACCOUNT env var. Exiting.");
  process.exit(1);
}

let serviceAccount;

try {
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
} catch (err) {
  console.error("❌ FIREBASE_SERVICE_ACCOUNT JSON is invalid.");
  console.error(err);
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert({
    ...serviceAccount,
    private_key: serviceAccount.private_key.replace(/\\n/g, "\n"), // IMPORTANT FIX
  }),
});

const firestore = admin.firestore();
const firebaseAuth = admin.auth();

/* ----------------------------------------------------
   SERVER INIT
---------------------------------------------------- */
const app = express();
app.use(cors());
app.use(express.json());

/* ----------------------------------------------------
   MONGO CONNECT
---------------------------------------------------- */
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.log("MongoDB Error:", err));

/* ----------------------------------------------------
   MODELS
---------------------------------------------------- */
const SOPSchema = new mongoose.Schema({
  ownerId: { type: String, required: true },
  title: { type: String, required: true },
  dept: { type: String, required: true },
  content: { type: String, required: true },
  updated: { type: Date, default: Date.now },
});

const EmployeeSchema = new mongoose.Schema({
  ownerId: { type: String, required: true },
  firebaseUid: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  email: { type: String, required: true },
  dept: { type: String, required: true },
  role: {
    type: String,
    enum: ["owner", "manager", "staff"],
    default: "staff",
  },
  status: { type: String, enum: ["active", "inactive"], default: "active" },
  createdAt: { type: Date, default: Date.now },
});

const SOP = mongoose.model("SOP", SOPSchema);
const Employee = mongoose.model("Employee", EmployeeSchema);

/* ----------------------------------------------------
   KEEP ALIVE
---------------------------------------------------- */
app.get("/ping", (req, res) => {
  res.json({ status: "active", time: new Date() });
});

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

/* ----------------------------------------------------
   AUTH MIDDLEWARE
---------------------------------------------------- */
async function authenticate(req, res, next) {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer "))
    return res.status(401).json({ message: "Missing token" });

  const idToken = authHeader.split(" ")[1];

  try {
    const decoded = await firebaseAuth.verifyIdToken(idToken);
    req.userUid = decoded.uid;
    next();
  } catch (err) {
    console.error("❌ Token verify error:", err);
    return res.status(401).json({ message: "Invalid token" });
  }
}

async function requireAdmin(req, res, next) {
  try {
    const doc = await firestore.doc(`users/${req.userUid}`).get();
    if (!doc.exists)
      return res.status(403).json({ message: "Role not found" });

    const data = doc.data();

    if (data.role !== "admin")
      return res.status(403).json({ message: "Admin access required" });

    next();
  } catch (err) {
    console.error("requireAdmin error", err);
    res.status(500).json({ message: "Server error" });
  }
}

/* ----------------------------------------------------
   ROUTES
---------------------------------------------------- */

// ---------- EMPLOYEES ----------
app.post("/api/employees", authenticate, requireAdmin, async (req, res) => {
  try {
    const { name, email, dept, role = "staff", status = "active", password } =
      req.body;

    if (!name || !email || !dept || !password) {
      return res
        .status(400)
        .json({ message: "Missing required fields (name,email,dept,password)" });
    }

    const fbUser = await firebaseAuth.createUser({
      email,
      password,
      displayName: name,
    });

    await firestore.doc(`users/${fbUser.uid}`).set({
      email,
      role: "employee",
      createdAt: Date.now(),
      ownerId: req.userUid,
    });

    const employee = new Employee({
      ownerId: req.userUid,
      firebaseUid: fbUser.uid,
      name,
      email,
      dept,
      role,
      status,
    });

    await employee.save();

    res.json({ message: "Employee Added", employee });
  } catch (err) {
    console.error("POST /api/employees err", err);
    if (err.code === 11000)
      return res.status(400).json({ message: "Employee already exists" });
    res.status(500).json({ message: "Failed to create employee" });
  }
});

// ---------- GET ALL EMPLOYEES ----------
app.get("/api/employees", authenticate, requireAdmin, async (req, res) => {
  try {
    const employees = await Employee.find({ ownerId: req.userUid }).sort({
      createdAt: -1,
    });
    res.json(employees);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch employees" });
  }
});

// GET SINGLE EMPLOYEE
app.get("/api/employees/:id", authenticate, requireAdmin, async (req, res) => {
  try {
    const emp = await Employee.findById(req.params.id);
    if (!emp || emp.ownerId !== req.userUid)
      return res.status(404).json({ message: "Employee not found" });

    res.json(emp);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch employee" });
  }
});

// UPDATE EMPLOYEE
app.put("/api/employees/:id", authenticate, requireAdmin, async (req, res) => {
  try {
    const emp = await Employee.findById(req.params.id);
    if (!emp || emp.ownerId !== req.userUid)
      return res.status(404).json({ message: "Employee not found" });

    if (req.body.email || req.body.name) {
      const updates = {};
      if (req.body.email) updates.email = req.body.email;
      if (req.body.name) updates.displayName = req.body.name;

      try {
        await firebaseAuth.updateUser(emp.firebaseUid, updates);
        await firestore.doc(`users/${emp.firebaseUid}`).update({
          email: req.body.email || emp.email,
        });
      } catch (e) {
        console.warn("Could not update firebase user", e);
      }
    }

    const updated = await Employee.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
    });

    res.json({ message: "Employee Updated", updated });
  } catch (err) {
    res.status(500).json({ message: "Failed to update employee" });
  }
});

// DELETE EMPLOYEE
app.delete("/api/employees/:id", authenticate, requireAdmin, async (req, res) => {
  try {
    const emp = await Employee.findById(req.params.id);
    if (!emp || emp.ownerId !== req.userUid)
      return res.status(404).json({ message: "Employee not found" });

    try {
      await firebaseAuth.deleteUser(emp.firebaseUid);
    } catch (e) {
      console.warn("Failed to delete firebase user:", e.message);
    }

    await Employee.findByIdAndDelete(req.params.id);
    await firestore.doc(`users/${emp.firebaseUid}`).delete().catch(() => { });

    res.json({ message: "Employee Deleted" });
  } catch (err) {
    res.status(500).json({ message: "Failed to delete employee" });
  }
});

// ---------- SOP CRUD ----------
app.post("/api/sops", authenticate, requireAdmin, async (req, res) => {
  try {
    const { title, dept, content } = req.body;
    if (!title || !dept || !content)
      return res.status(400).json({ message: "Missing fields" });

    const sop = new SOP({
      ownerId: req.userUid,
      title,
      dept,
      content,
    });

    await sop.save();

    res.json({ message: "SOP Created Successfully", sop });
  } catch (err) {
    res.status(500).json({ message: "Failed to create SOP" });
  }
});

// GET ALL
app.get("/api/sops", authenticate, requireAdmin, async (req, res) => {
  try {
    const sops = await SOP.find({ ownerId: req.userUid }).sort({
      updated: -1,
    });

    res.json(sops);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch SOPs" });
  }
});

// GET RECENT
app.get("/api/sops/recent", authenticate, requireAdmin, async (req, res) => {
  try {
    const sops = await SOP.find({ ownerId: req.userUid })
      .sort({ updated: -1 })
      .limit(3);

    res.json(sops);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch recent SOPs" });
  }
});

// GET SINGLE SOP
app.get("/api/sops/:id", authenticate, requireAdmin, async (req, res) => {
  try {
    const sop = await SOP.findById(req.params.id);
    if (!sop || sop.ownerId !== req.userUid)
      return res.status(404).json({ message: "SOP not found" });

    res.json(sop);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch SOP" });
  }
});

// UPDATE SOP
app.put("/api/sops/:id", authenticate, requireAdmin, async (req, res) => {
  try {
    const sop = await SOP.findById(req.params.id);
    if (!sop || sop.ownerId !== req.userUid)
      return res.status(404).json({ message: "SOP not found" });

    const updated = await SOP.findByIdAndUpdate(
      req.params.id,
      { ...req.body, updated: Date.now() },
      { new: true }
    );

    res.json({ message: "SOP Updated", updated });
  } catch (err) {
    res.status(500).json({ message: "Failed to update SOP" });
  }
});

// DELETE SOP
app.delete("/api/sops/:id", authenticate, requireAdmin, async (req, res) => {
  try {
    const sop = await SOP.findById(req.params.id);
    if (!sop || sop.ownerId !== req.userUid)
      return res.status(404).json({ message: "SOP not found" });

    await SOP.findByIdAndDelete(req.params.id);

    res.json({ message: "SOP Deleted" });
  } catch (err) {
    res.status(500).json({ message: "Failed to delete SOP" });
  }
});

/* ----------------------------------------------------
   STATS
---------------------------------------------------- */
app.get("/api/stats", authenticate, requireAdmin, async (req, res) => {
  try {
    const totalEmployees = await Employee.countDocuments({
      ownerId: req.userUid,
    });

    const totalSOPs = await SOP.countDocuments({
      ownerId: req.userUid,
    });

    res.json({
      employees: totalEmployees,
      activeTrainings: 0,
      completedTrainings: 0,
      pendingSOPs: totalSOPs,
    });
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch stats" });
  }
});

/* ----------------------------------------------------
   SERVER START
---------------------------------------------------- */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
