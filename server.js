import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import cron from "node-cron";
import fetch from "node-fetch";
import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";
import admin from "firebase-admin";

dotenv.config();

/*
  REQUIRED ENV:
  - MONGO_URI
  - FIREBASE_PROJECT_ID
  - FIREBASE_ADMIN_CERT (full JSON service account)
  - SERVER_URL (optional for keepalive)
  - PORT
*/

if (!process.env.MONGO_URI) {
  console.error("Missing MONGO_URI");
  process.exit(1);
}
if (!process.env.FIREBASE_PROJECT_ID) {
  console.error("Missing FIREBASE_PROJECT_ID");
  process.exit(1);
}

/* ----------------------------------------
   INIT FIREBASE ADMIN
---------------------------------------- */
let firebaseAdminInitialized = false;

try {
  const cert = JSON.parse(process.env.FIREBASE_ADMIN_CERT);

  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert(cert),
    });
  }

  console.log("✅ Firebase Admin initialized");
  firebaseAdminInitialized = true;
} catch (err) {
  console.log("⚠️ Firebase Admin not initialized:", err.message);
}

/* ----------------------------------------
   JWKS TOKEN VERIFICATION
---------------------------------------- */
const client = jwksClient({
  jwksUri:
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com",
  cache: true,
  cacheMaxEntries: 10,
  cacheMaxAge: 10 * 60 * 1000,
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    callback(null, key.getPublicKey());
  });
}

function verifyFirebaseToken(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(
      token,
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

/* ----------------------------------------
   EXPRESS INIT
---------------------------------------- */
const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

/* ----------------------------------------
   MONGO CONNECT
---------------------------------------- */
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => {
    console.error("Mongo error:", err);
    process.exit(1);
  });

/* ----------------------------------------
   MODELS
---------------------------------------- */
const UserSchema = new mongoose.Schema({
  firebaseUid: String,
  email: String,
  role: { type: String, enum: ["user", "admin"], default: "user" },
  createdAt: { type: Date, default: Date.now },
});

const EmployeeSchema = new mongoose.Schema({
  ownerId: String,
  firebaseUid: String,
  name: String,
  email: String,
  dept: String,
  role: { type: String, enum: ["owner", "manager", "staff"], default: "staff" },
  status: { type: String, enum: ["active", "inactive"], default: "active" },
  createdAt: { type: Date, default: Date.now },
});

const SOPSchema = new mongoose.Schema({
  ownerId: String,
  title: String,
  dept: String,
  content: String,
  updated: { type: Date, default: Date.now },
});

const User = mongoose.model("User", UserSchema);
const Employee = mongoose.model("Employee", EmployeeSchema);
const SOP = mongoose.model("SOP", SOPSchema);

/* ----------------------------------------
   KEEP SERVER ALIVE
---------------------------------------- */
app.get("/ping", (req, res) =>
  res.json({ status: "active", time: new Date() })
);

if (process.env.SERVER_URL) {
  cron.schedule("*/14 * * * *", async () => {
    try {
      await fetch(process.env.SERVER_URL + "/ping");
      console.log("Ping sent.");
    } catch {}
  });
}

/* ----------------------------------------
   AUTH MIDDLEWARE
---------------------------------------- */
async function authenticate(req, res, next) {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer "))
    return res.status(401).json({ message: "Missing token" });

  const token = authHeader.split(" ")[1];

  try {
    const decoded = await verifyFirebaseToken(token);

    let user = await User.findOne({ firebaseUid: decoded.user_id });
    if (!user) {
      user = await new User({
        firebaseUid: decoded.user_id,
        email: decoded.email,
      }).save();
    }

    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

function requireAdmin(req, res, next) {
  return req.user.role === "admin"
    ? next()
    : res.status(403).json({ message: "Admin only" });
}

/* ----------------------------------------
   EMPLOYEE: /api/employees/me
---------------------------------------- */
app.get("/api/employees/me", authenticate, async (req, res) => {
  const emp = await Employee.findOne({ firebaseUid: req.user.firebaseUid });

  if (!emp) return res.status(404).json({ message: "Employee not found" });
  if (emp.status !== "active")
    return res.status(403).json({ message: "Account inactive" });

  if (emp.role === "admin")
    return res.status(403).json({ message: "Admins can't login here" });

  res.json(emp);
});

/* ----------------------------------------
   ADMIN REGISTER
---------------------------------------- */
app.post("/api/users/register-admin", authenticate, async (req, res) => {
  const updated = await User.findOneAndUpdate(
    { firebaseUid: req.user.firebaseUid },
    { role: "admin" },
    { new: true }
  );

  res.json({ message: "Registered admin", updated });
});

/* ----------------------------------------
   ADMIN GET OWN INFO
---------------------------------------- */
app.get("/api/users/me", authenticate, (req, res) => {
  res.json(req.user);
});

/* ----------------------------------------
   EMPLOYEES CRUD
---------------------------------------- */
app.post("/api/employees", authenticate, requireAdmin, async (req, res) => {
  const { name, email, dept } = req.body;

  if (!name || !email || !dept)
    return res.status(400).json({ message: "Missing fields" });

  let firebaseUid = null;

  if (!firebaseAdminInitialized) {
    return res
      .status(400)
      .json({ message: "Firebase admin not initialized on server" });
  }

  let fbUser = null;

  try {
    fbUser = await admin.auth().getUserByEmail(email);
  } catch {}

  if (!fbUser) {
    fbUser = await admin.auth().createUser({
      email,
      password: "Temp" + Math.floor(1000 + Math.random() * 9000),
    });
  }

  firebaseUid = fbUser.uid;

  const emp = await new Employee({
    ownerId: req.user.firebaseUid,
    firebaseUid,
    name,
    email,
    dept,
  }).save();

  res.json({ message: "Employee created", emp });
});

app.get("/api/employees", authenticate, requireAdmin, async (req, res) => {
  const list = await Employee.find({
    ownerId: req.user.firebaseUid,
  }).sort({ createdAt: -1 });

  res.json(list);
});

app.put("/api/employees/:id", authenticate, requireAdmin, async (req, res) => {
  const updated = await Employee.findOneAndUpdate(
    { _id: req.params.id, ownerId: req.user.firebaseUid },
    req.body,
    { new: true }
  );

  if (!updated) return res.status(404).json({ message: "Employee not found" });

  res.json(updated);
});

app.delete("/api/employees/:id", authenticate, requireAdmin, async (req, res) => {
  const deleted = await Employee.findOneAndDelete({
    _id: req.params.id,
    ownerId: req.user.firebaseUid,
  });

  if (!deleted) return res.status(404).json({ message: "Employee not found" });

  res.json({ message: "Deleted" });
});

/* ----------------------------------------
   SOP CRUD
---------------------------------------- */
app.post("/api/sops", authenticate, requireAdmin, async (req, res) => {
  const sop = await new SOP({
    ownerId: req.user.firebaseUid,
    ...req.body,
  }).save();

  res.json(sop);
});

app.get("/api/sops", authenticate, requireAdmin, async (req, res) => {
  res.json(
    await SOP.find({ ownerId: req.user.firebaseUid }).sort({ updated: -1 })
  );
});

app.get("/api/sops/:id", authenticate, requireAdmin, async (req, res) => {
  const sop = await SOP.findOne({
    _id: req.params.id,
    ownerId: req.user.firebaseUid,
  });

  if (!sop) return res.status(404).json({ message: "SOP not found" });

  res.json(sop);
});

app.delete("/api/sops/:id", authenticate, requireAdmin, async (req, res) => {
  const deleted = await SOP.findOneAndDelete({
    _id: req.params.id,
    ownerId: req.user.firebaseUid,
  });

  if (!deleted) return res.status(404).json({ message: "SOP not found" });

  res.json({ message: "Deleted" });
});

/* ----------------------------------------
   STATS
---------------------------------------- */
app.get("/api/stats", authenticate, requireAdmin, async (req, res) => {
  const employees = await Employee.countDocuments({
    ownerId: req.user.firebaseUid,
  });

  const sops = await SOP.countDocuments({ ownerId: req.user.firebaseUid });

  res.json({
    employees,
    activeTrainings: 0,
    completedTrainings: 0,
    pendingSOPs: sops,
  });
});

/* ----------------------------------------
   START SERVER
---------------------------------------- */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log("Server running on " + PORT));
