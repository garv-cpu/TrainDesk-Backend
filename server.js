import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import cron from "node-cron";
import fetch from "node-fetch";
import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";

dotenv.config();

/*
  IMPORTANT ENV VARS:
  - MONGO_URI
  - SERVER_URL (optional, used by keep-alive)
  - FIREBASE_PROJECT_ID (your firebase project id, used as JWT audience)
  - INIT_ADMINS (optional comma-separated list of emails that should be admins initially)
*/

// ---------- JWKS / Firebase token verification ----------
// Google's JWKS for securetoken (Firebase ID tokens)
const jwksUri =
  "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";

const client = jwksClient({
  jwksUri,
  timeout: 30000,
  cache: true,
  cacheMaxEntries: 5,
  cacheMaxAge: 10 * 60 * 1000,
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    const pubKey = key.getPublicKey();
    callback(null, pubKey);
  });
}

function verifyFirebaseToken(idToken) {
  return new Promise((resolve, reject) => {
    if (!process.env.FIREBASE_PROJECT_ID) {
      return reject(new Error("Missing FIREBASE_PROJECT_ID env var"));
    }

    jwt.verify(
      idToken,
      getKey,
      {
        algorithms: ["RS256"],
        issuer: `https://securetoken.google.com/${process.env.FIREBASE_PROJECT_ID}`,
        audience: process.env.FIREBASE_PROJECT_ID,
      },
      (err, decoded) => {
        if (err) return reject(err);
        resolve(decoded);
      }
    );
  });
}

// ---------- App init ----------
const app = express();
app.use(cors());
app.use(express.json());

// ---------- Mongo connect ----------
if (!process.env.MONGO_URI) {
  console.error("Missing MONGO_URI in env");
  process.exit(1);
}

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => {
    console.error("MongoDB connect error:", err);
    process.exit(1);
  });

// ---------- Models ----------
const UserSchema = new mongoose.Schema({
  firebaseUid: { type: String, required: true, unique: true },
  email: { type: String, required: true },
  role: { type: String, enum: ["admin", "staff"], default: "staff" },
  createdAt: { type: Date, default: Date.now },
  // optional ownerId for multi-level ownership if needed later
});

const SOPSchema = new mongoose.Schema({
  ownerId: { type: String, required: true }, // firebase uid of admin/owner
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

const User = mongoose.model("User", UserSchema);
const SOP = mongoose.model("SOP", SOPSchema);
const Employee = mongoose.model("Employee", EmployeeSchema);

// ---------- Keep-alive ----------
app.get("/ping", (req, res) => res.json({ status: "active", time: new Date() }));

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

// ---------- Auth middleware ----------
// Authenticate: verify token (via JWKS) and upsert user in Mongo (first-time sign-in)
async function authenticate(req, res, next) {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Missing token" });
  }
  const idToken = authHeader.split(" ")[1];

  try {
    const decoded = await verifyFirebaseToken(idToken);
    // decoded contains: uid, email, name, etc.
    const uid = decoded.user_id || decoded.sub || decoded.uid;
    const email = decoded.email;

    if (!uid || !email) {
      return res.status(401).json({ message: "Invalid token payload" });
    }

    // Upsert user in Mongo: auto-create first time
    let user = await User.findOne({ firebaseUid: uid });
    if (!user) {
      // If user's email is in INIT_ADMINS list, make admin
      const initAdmins = (process.env.INIT_ADMINS || "")
        .split(",")
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean);

      const role = initAdmins.includes(email.toLowerCase()) ? "admin" : "staff";

      user = new User({
        firebaseUid: uid,
        email,
        role,
      });
      await user.save();
      console.log(`Auto-created user ${email} as ${role}`);
    }

    // attach to request
    req.user = {
      uid,
      email,
      role: user.role,
      dbId: user._id,
    };

    next();
  } catch (err) {
    console.error("Token verification error:", err);
    return res.status(401).json({ message: "Invalid token" });
  }
}

// Require admin role middleware (reads req.user.role)
function requireAdmin(req, res, next) {
  if (!req.user) return res.status(401).json({ message: "Not authenticated" });
  if (req.user.role !== "admin") return res.status(403).json({ message: "Admin access required" });
  next();
}

// ------------------ ROUTES ------------------

// Create employee (admin) - this does NOT create firebase auth user (client should handle invites).
// If you want the server to create Firebase users, you'd need service account; avoided here.
app.post("/api/employees", authenticate, requireAdmin, async (req, res) => {
  try {
    const { name, email, dept, role = "staff", status = "active", firebaseUid } = req.body;

    if (!name || !email || !dept) {
      return res.status(400).json({ message: "Missing required fields (name,email,dept)" });
    }

    // firebaseUid optional — if client created the user in Firebase, pass firebaseUid to link
    if (!firebaseUid) {
      // if you don't have firebaseUid, generate a placeholder or require it.
      // For now require firebaseUid to keep uniqueness guarantee:
      return res.status(400).json({ message: "firebaseUid is required for employee creation" });
    }

    const exists = await Employee.findOne({ firebaseUid });
    if (exists) return res.status(400).json({ message: "Employee already exists" });

    const employee = new Employee({
      ownerId: req.user.uid,
      firebaseUid,
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
    res.status(500).json({ message: "Failed to create employee" });
  }
});

// GET employees (tenant scoped)
app.get("/api/employees", authenticate, requireAdmin, async (req, res) => {
  try {
    const employees = await Employee.find({ ownerId: req.user.uid }).sort({ createdAt: -1 });
    res.json(employees);
  } catch (err) {
    console.error("GET /api/employees err", err);
    res.status(500).json({ message: "Failed to fetch employees" });
  }
});

app.get("/api/employees/:id", authenticate, requireAdmin, async (req, res) => {
  try {
    const emp = await Employee.findById(req.params.id);
    if (!emp || emp.ownerId !== req.user.uid) return res.status(404).json({ message: "Employee not found" });
    res.json(emp);
  } catch (err) {
    console.error("GET /api/employees/:id err", err);
    res.status(500).json({ message: "Failed to fetch employee" });
  }
});

app.put("/api/employees/:id", authenticate, requireAdmin, async (req, res) => {
  try {
    const emp = await Employee.findById(req.params.id);
    if (!emp || emp.ownerId !== req.user.uid) return res.status(404).json({ message: "Employee not found" });

    const updated = await Employee.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json({ message: "Employee Updated", updated });
  } catch (err) {
    console.error("PUT /api/employees/:id err", err);
    res.status(500).json({ message: "Failed to update employee" });
  }
});

app.delete("/api/employees/:id", authenticate, requireAdmin, async (req, res) => {
  try {
    const emp = await Employee.findById(req.params.id);
    if (!emp || emp.ownerId !== req.user.uid) return res.status(404).json({ message: "Employee not found" });

    await Employee.findByIdAndDelete(req.params.id);
    res.json({ message: "Employee Deleted" });
  } catch (err) {
    console.error("DELETE /api/employees/:id err", err);
    res.status(500).json({ message: "Failed to delete employee" });
  }
});

// ---------- SOPs ----------
app.post("/api/sops", authenticate, requireAdmin, async (req, res) => {
  try {
    const { title, dept, content } = req.body;
    if (!title || !dept || !content) return res.status(400).json({ message: "Missing fields" });

    const sop = new SOP({ ownerId: req.user.uid, title, dept, content });
    await sop.save();
    res.json({ message: "SOP Created Successfully", sop });
  } catch (err) {
    console.error("POST /api/sops err", err);
    res.status(500).json({ message: "Failed to create SOP" });
  }
});

app.get("/api/sops", authenticate, requireAdmin, async (req, res) => {
  try {
    const sops = await SOP.find({ ownerId: req.user.uid }).sort({ updated: -1 });
    res.json(sops);
  } catch (err) {
    console.error("GET /api/sops err", err);
    res.status(500).json({ message: "Failed to fetch SOPs" });
  }
});

app.get("/api/sops/recent", authenticate, requireAdmin, async (req, res) => {
  try {
    const sops = await SOP.find({ ownerId: req.user.uid }).sort({ updated: -1 }).limit(3);
    res.json(sops);
  } catch (err) {
    console.error("GET /api/sops/recent err", err);
    res.status(500).json({ message: "Failed to fetch recent SOPs" });
  }
});

app.get("/api/sops/:id", authenticate, requireAdmin, async (req, res) => {
  try {
    const sop = await SOP.findById(req.params.id);
    if (!sop || sop.ownerId !== req.user.uid) return res.status(404).json({ message: "SOP not found" });
    res.json(sop);
  } catch (err) {
    console.error("GET /api/sops/:id err", err);
    res.status(500).json({ message: "Failed to fetch SOP" });
  }
});

app.put("/api/sops/:id", authenticate, requireAdmin, async (req, res) => {
  try {
    const sop = await SOP.findById(req.params.id);
    if (!sop || sop.ownerId !== req.user.uid) return res.status(404).json({ message: "SOP not found" });
    const updated = await SOP.findByIdAndUpdate(req.params.id, { ...req.body, updated: Date.now() }, { new: true });
    res.json({ message: "SOP Updated", updated });
  } catch (err) {
    console.error("PUT /api/sops/:id err", err);
    res.status(500).json({ message: "Failed to update SOP" });
  }
});

app.delete("/api/sops/:id", authenticate, requireAdmin, async (req, res) => {
  try {
    const sop = await SOP.findById(req.params.id);
    if (!sop || sop.ownerId !== req.user.uid) return res.status(404).json({ message: "SOP not found" });
    await SOP.findByIdAndDelete(req.params.id);
    res.json({ message: "SOP Deleted" });
  } catch (err) {
    console.error("DELETE /api/sops/:id err", err);
    res.status(500).json({ message: "Failed to delete SOP" });
  }
});

// ---------- Stats ----------
app.get("/api/stats", authenticate, requireAdmin, async (req, res) => {
  try {
    const totalEmployees = await Employee.countDocuments({ ownerId: req.user.uid });
    const totalSOPs = await SOP.countDocuments({ ownerId: req.user.uid });
    res.json({ employees: totalEmployees, activeTrainings: 0, completedTrainings: 0, pendingSOPs: totalSOPs });
  } catch (err) {
    console.error("GET /api/stats err", err);
    res.status(500).json({ message: "Failed to fetch stats" });
  }
});

// ---------- Start ----------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
