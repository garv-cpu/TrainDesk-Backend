// server.js
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import cron from "node-cron";
import fetch from "node-fetch";
import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";
import admin from "firebase-admin";
import { v2 as cloudinary } from "cloudinary";
import crypto from "crypto";

dotenv.config();

console.log("Loaded Cloudinary ENV:", {
  name: process.env.CLOUDINARY_CLOUD_NAME,
  key: process.env.CLOUDINARY_API_KEY,
  secret: process.env.CLOUDINARY_API_SECRET ? "YES" : "NO",
});

/* ----------------------------------------
   REQUIRED ENV check
---------------------------------------- */
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
app.use(express.json({ limit: "8mb" })); // increased limit for safety (videos are uploaded to cloudinary not server)

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
   MODELS (updated TrainingVideo schema)
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
  // optional: track completed trainings per employee
  completedTrainings: [{ type: mongoose.Schema.Types.ObjectId, ref: "TrainingVideo" }],
  pendingSOPs: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
});

const SOPSchema = new mongoose.Schema({
  ownerId: String,
  title: String,
  dept: String,
  content: String,
  updated: { type: Date, default: Date.now },
});

/*
  TrainingVideo schema: 
  - status: 'active' | 'completed'
  - completedBy: array of employee firebaseUids (who completed)
*/
const TrainingVideoSchema = new mongoose.Schema({
  ownerId: String, // Admin UID
  title: String,
  description: String,
  videoUrl: String,
  thumbnailUrl: String,
  assignedEmployees: [String], // employee firebaseUids (empty => public to all)
  status: { type: String, enum: ["active", "completed"], default: "active" },
  completedBy: [String], // employee firebaseUids who marked complete
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", UserSchema);
const Employee = mongoose.model("Employee", EmployeeSchema);
const SOP = mongoose.model("SOP", SOPSchema);
const TrainingVideo = mongoose.model("TrainingVideo", TrainingVideoSchema);

/* ----------------------------------------
   CLOUDINARY
---------------------------------------- */
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

/* ----------------------------------------
   KEEP SERVER ALIVE
---------------------------------------- */
app.get("/ping", (req, res) => res.json({ status: "active", time: new Date() }));

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
  if (!authHeader.startsWith("Bearer ")) return res.status(401).json({ message: "Missing token" });

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
  return req.user.role === "admin" ? next() : res.status(403).json({ message: "Admin only" });
}

/* ----------------------------------------
   CLOUDINARY SIGNATURE (unchanged)
---------------------------------------- */
app.get("/api/cloudinary-signature", (req, res) => {
  try {
    const timestamp = Math.round(Date.now() / 1000);
    const folder = req.query.folder || "training_videos";

    // use cloudinary utils to sign
    const signature = cloudinary.utils.api_sign_request({ timestamp, folder }, process.env.CLOUDINARY_API_SECRET);

    res.json({
      signature,
      timestamp,
      folder,
      apiKey: process.env.CLOUDINARY_API_KEY,
      cloudName: process.env.CLOUDINARY_CLOUD_NAME,
    });
  } catch (err) {
    console.error("Cloudinary Signature Error", err);
    res.status(500).json({ error: "Cannot generate signature" });
  }
});

/* ----------------------------------------
   TRAINING ROUTES (updated)
---------------------------------------- */

// Get single training (admin)
app.get("/api/training/:id", authenticate, requireAdmin, async (req, res) => {
  try {
    const video = await TrainingVideo.findOne({
      _id: req.params.id,
      ownerId: req.user.firebaseUid,
    });

    if (!video) return res.status(404).json({ message: "Training video not found" });

    res.json(video);
  } catch (err) {
    console.error("Training fetch error:", err);
    res.status(500).json({ message: "Failed to fetch training video" });
  }
});

// Create training (admin)
app.post("/api/training", authenticate, requireAdmin, async (req, res) => {
  try {
    const { title, description, videoUrl, thumbnailUrl, assignedEmployees, status } = req.body;

    if (!title || !videoUrl) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    let finalThumbnail = thumbnailUrl;
    if (!thumbnailUrl) {
      finalThumbnail = videoUrl.replace("/upload/", "/upload/so_1/"); // frame at 1 second
    }

    const training = await new TrainingVideo({
      ownerId: req.user.firebaseUid,
      title,
      description,
      videoUrl,
      thumbnailUrl: finalThumbnail,
      assignedEmployees: assignedEmployees || [],
      status: status === "completed" ? "completed" : "active",
    }).save();

    res.json(training);
  } catch (err) {
    console.log("Training create error:", err);
    res.status(500).json({ message: "Failed to create training" });
  }
});

// List trainings (admin)
app.get("/api/training", authenticate, requireAdmin, async (req, res) => {
  const list = await TrainingVideo.find({
    ownerId: req.user.firebaseUid,
  }).sort({ createdAt: -1 });

  res.json(list);
});

// Delete training (admin)
app.delete("/api/training/:id", authenticate, requireAdmin, async (req, res) => {
  const deleted = await TrainingVideo.findOneAndDelete({
    _id: req.params.id,
    ownerId: req.user.firebaseUid,
  });

  if (!deleted) return res.status(404).json({ message: "Training video not found" });

  res.json({ message: "Deleted" });
});

/* ----------------------------------------
   EMPLOYEE training endpoints (view & complete)
---------------------------------------- */

// Employee: list available trainings (public or assigned)
app.get("/api/employee/training", authenticate, async (req, res) => {
  const emp = await Employee.findOne({ firebaseUid: req.user.firebaseUid });
  if (!emp) return res.status(404).json({ message: "Employee not found" });

  const videos = await TrainingVideo.find({
    ownerId: emp.ownerId,
    $or: [{ assignedEmployees: [] }, { assignedEmployees: emp.firebaseUid }],
  }).sort({ createdAt: -1 });

  res.json(videos);
});

// Employee: get single training (if allowed)
app.get("/api/employee/training/:id", authenticate, async (req, res) => {
  const emp = await Employee.findOne({ firebaseUid: req.user.firebaseUid });
  if (!emp) return res.status(404).json({ message: "Employee not found" });

  const video = await TrainingVideo.findOne({
    _id: req.params.id,
    ownerId: emp.ownerId,
    $or: [{ assignedEmployees: [] }, { assignedEmployees: emp.firebaseUid }],
  });

  if (!video) return res.status(404).json({ message: "Video not found" });

  res.json(video);
});

// Employee: mark training complete for themselves
app.post("/api/training/:id/complete", authenticate, async (req, res) => {
  try {
    const emp = await Employee.findOne({ firebaseUid: req.user.firebaseUid });
    if (!emp) return res.status(404).json({ message: "Employee not found" });

    const training = await TrainingVideo.findById(req.params.id);
    if (!training) return res.status(404).json({ message: "Training not found" });

    // check access: training should belong to employee's owner
    if (training.ownerId !== emp.ownerId) return res.status(403).json({ message: "Not allowed" });

    // check assignedEmployees (if assigned and employee not in list -> forbidden)
    if (training.assignedEmployees && training.assignedEmployees.length > 0) {
      if (!training.assignedEmployees.includes(emp.firebaseUid)) {
        return res.status(403).json({ message: "Training not assigned to you" });
      }
    }

    // add employee to completedBy if not present
    if (!training.completedBy.includes(emp.firebaseUid)) {
      training.completedBy.push(emp.firebaseUid);
    }

    // decide whether to mark training status 'completed':
    // - if no assignedEmployees (public), mark completed when any one completes (you can change this)
    // - if assignedEmployees exist, mark completed only when all assigned employees have completed
    if (!training.assignedEmployees || training.assignedEmployees.length === 0) {
      training.status = "completed";
    } else {
      const allCompleted = training.assignedEmployees.every((a) => training.completedBy.includes(a));
      if (allCompleted) training.status = "completed";
    }

    await training.save();

    // optionally add to employee.completedTrainings
    if (!emp.completedTrainings.includes(training._id)) {
      emp.completedTrainings.push(training._id);
      await emp.save();
    }

    res.json({ message: "Marked complete", training });
  } catch (err) {
    console.error("Mark complete error:", err);
    res.status(500).json({ message: "Failed to mark complete" });
  }
});

// Admin: force mark training completed
app.post("/api/training/:id/mark-complete", authenticate, requireAdmin, async (req, res) => {
  try {
    const training = await TrainingVideo.findOne({ _id: req.params.id, ownerId: req.user.firebaseUid });
    if (!training) return res.status(404).json({ message: "Training not found" });

    training.status = "completed";
    await training.save();

    res.json({ message: "Training force-marked completed", training });
  } catch (err) {
    console.error("Admin mark complete error:", err);
    res.status(500).json({ message: "Failed to mark complete" });
  }
});

/* ----------------------------------------
   EMPLOYEE: /api/employees/me
---------------------------------------- */
app.get("/api/employees/me", authenticate, async (req, res) => {
  const emp = await Employee.findOne({ firebaseUid: req.user.firebaseUid });

  if (!emp) return res.status(404).json({ message: "Employee not found" });
  if (emp.status !== "active") return res.status(403).json({ message: "Account inactive" });

  if (emp.role === "admin") return res.status(403).json({ message: "Admins can't login here" });

  res.json(emp);
});

/* ----------------------------------------
   ADMIN REGISTER & users/me (unchanged)
---------------------------------------- */
app.post("/api/users/register-admin", authenticate, async (req, res) => {
  const updated = await User.findOneAndUpdate({ firebaseUid: req.user.firebaseUid }, { role: "admin" }, { new: true });
  res.json({ message: "Registered admin", updated });
});

app.get("/api/users/me", authenticate, (req, res) => {
  res.json(req.user);
});

/* ----------------------------------------
   EMPLOYEES CRUD (unchanged)
---------------------------------------- */
app.post("/api/employees", authenticate, requireAdmin, async (req, res) => {
  const { name, email, dept } = req.body;

  if (!name || !email || !dept) return res.status(400).json({ message: "Missing fields" });

  let firebaseUid = null;

  if (!firebaseAdminInitialized) {
    return res.status(400).json({ message: "Firebase admin not initialized on server" });
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
  const list = await Employee.find({ ownerId: req.user.firebaseUid }).sort({ createdAt: -1 });
  res.json(list);
});

app.put("/api/employees/:id", authenticate, requireAdmin, async (req, res) => {
  const updated = await Employee.findOneAndUpdate({ _id: req.params.id, ownerId: req.user.firebaseUid }, req.body, { new: true });
  if (!updated) return res.status(404).json({ message: "Employee not found" });
  res.json(updated);
});

app.delete("/api/employees/:id", authenticate, requireAdmin, async (req, res) => {
  const deleted = await Employee.findOneAndDelete({ _id: req.params.id, ownerId: req.user.firebaseUid });
  if (!deleted) return res.status(404).json({ message: "Employee not found" });
  res.json({ message: "Deleted" });
});

/* ----------------------------------------
   SOP CRUD
---------------------------------------- */
app.post("/api/sops", authenticate, requireAdmin, async (req, res) => {
  const sop = await new SOP({ ownerId: req.user.firebaseUid, ...req.body }).save();
  res.json(sop);
});

app.put("/api/sops/:id/clear", authenticate, async (req, res) => {
  const updated = await SOP.findByIdAndUpdate(req.params.id, { content: "" }, { new: true });
  res.json(updated);
});

app.get("/api/sops", authenticate, requireAdmin, async (req, res) => {
  res.json(await SOP.find({ ownerId: req.user.firebaseUid }).sort({ updated: -1 }));
});

app.get("/api/sops/:id", authenticate, requireAdmin, async (req, res) => {
  const sop = await SOP.findOne({ _id: req.params.id, ownerId: req.user.firebaseUid });
  if (!sop) return res.status(404).json({ message: "SOP not found" });
  res.json(sop);
});

app.delete("/api/sops/:id", authenticate, requireAdmin, async (req, res) => {
  const deleted = await SOP.findOneAndDelete({ _id: req.params.id, ownerId: req.user.firebaseUid });
  if (!deleted) return res.status(404).json({ message: "SOP not found" });
  res.json({ message: "Deleted" });
});

/* ----------------------------------------
   EMPLOYEE: GET SOP LIST
---------------------------------------- */
app.get("/api/employee/sops", authenticate, async (req, res) => {
  const emp = await Employee.findOne({ firebaseUid: req.user.firebaseUid });
  if (!emp) return res.status(404).json({ message: "Employee not found" });

  const sops = await SOP.find({ ownerId: emp.ownerId }).sort({ updated: -1 });
  res.json(sops);
});

app.get("/api/employee/sops/:id", authenticate, async (req, res) => {
  const emp = await Employee.findOne({ firebaseUid: req.user.firebaseUid });
  if (!emp) return res.status(404).json({ message: "Employee not found" });

  const sop = await SOP.findOne({ _id: req.params.id, ownerId: emp.ownerId });
  if (!sop) return res.status(404).json({ message: "SOP not found" });

  res.json(sop);
});

/* ----------------------------------------
   STATS (updated with real training counts)
---------------------------------------- */
app.get("/api/stats", authenticate, requireAdmin, async (req, res) => {
  try {
    const ownerId = req.user.firebaseUid;

    const employees = await Employee.countDocuments({ ownerId });
    const activeTrainings = await TrainingVideo.countDocuments({ ownerId, status: "active" });
    const completedTrainings = await TrainingVideo.countDocuments({ ownerId, status: "completed" });
    const sops = await SOP.countDocuments({ ownerId });

    res.json({
      employees,
      activeTrainings,
      completedTrainings,
      pendingSOPs: sops,
    });
  } catch (err) {
    console.error("Stats error:", err);
    res.status(500).json({ message: "Failed to fetch stats" });
  }
});

/* ----------------------------------------
   START SERVER
---------------------------------------- */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log("Server running on " + PORT));
