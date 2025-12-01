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
import http from "http";
import { Server } from "socket.io";
import PDFDocument from "pdfkit";
import fs from "fs";
import path from "path";

dotenv.config();

/* -------------------------------
   EXPRESS + SOCKET INIT
-------------------------------- */
const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: "*" },
});

/* Socket Connected */
io.on("connection", (socket) => {
  console.log("🔵 WebSocket connected:", socket.id);
});

/* Emit helper */
function emitToOwner(ownerId, event, data) {
  io.emit(`${ownerId}:${event}`, data);
}

/* ----------------------------------------
   Check Cloudinary ENV
---------------------------------------- */
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

export const uploadFile = async (localPath) => {
  try {
    const result = await cloudinary.uploader.upload(localPath, {
      folder: "hibonos/sop-certificates",
      resource_type: "auto",
    });

    // remove from temp
    fs.unlinkSync(localPath);

    return result.secure_url;
  } catch (err) {
    console.error("Cloudinary Upload Error:", err);
    throw new Error("Upload failed");
  }
};

export const generateCertificate = async ({ employeeName, sopTitle }) => {
  const doc = new PDFDocument({ size: "A4", layout: "landscape" });

  const filePath = path.join("temp", `${Date.now()}-cert.pdf`);
  const stream = fs.createWriteStream(filePath);
  doc.pipe(stream);

  doc.fontSize(28).text("Certificate of Completion", { align: "center" });
  doc.moveDown();
  doc.fontSize(18).text(`This certifies that`, { align: "center" });
  doc.moveDown();
  doc.fontSize(26).text(`${employeeName}`, { align: "center", bold: true });
  doc.moveDown();
  doc.fontSize(18).text(`has successfully completed the SOP:`, {
    align: "center",
  });
  doc.moveDown();
  doc.fontSize(24).text(`${sopTitle}`, { align: "center" });

  doc.end();

  await new Promise((resolve) => stream.on("finish", resolve));

  const remoteUrl = await uploadFile(filePath);

  fs.unlinkSync(filePath);

  return remoteUrl;
};

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
   EXPRESS
---------------------------------------- */
app.use(cors({
  origin: ["http://localhost:5173", "https://train-desk.vercel.app"],
  methods: "GET,POST,PUT,DELETE,OPTIONS",
  allowedHeaders: "Content-Type,Authorization",
  credentials: true
}));

// Handle OPTIONS for all routes (CORS preflight) — Express 5 compatible
app.options(/.*/, (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
  res.sendStatus(200);
});


app.use(express.json({ limit: "8mb" }));

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
  completedTrainings: [{ type: mongoose.Schema.Types.ObjectId, ref: "TrainingVideo" }],
  pendingSOPs: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  completedBy: [
    {
      empId: { type: mongoose.Schema.Types.ObjectId, ref: "Employee" },
      completedAt: Date,
    },
  ],
});

const SOPSchema = new mongoose.Schema({
  ownerId: String,
  title: String,
  dept: String,
  content: String,
  updated: { type: Date, default: Date.now },
  assignedTo: [
    { type: mongoose.Schema.Types.ObjectId, ref: "Employee" }
  ]
});

const TrainingVideoSchema = new mongoose.Schema({
  ownerId: String,
  title: String,
  description: String,
  videoUrl: String,
  thumbnailUrl: String,
  assignedEmployees: [String],
  status: { type: String, enum: ["active", "completed"], default: "active" },
  completedBy: [String],
  createdAt: { type: Date, default: Date.now },
});

const SystemLogSchema = new mongoose.Schema({
  ownerId: String,
  message: String,
  type: { type: String },
  createdAt: { type: Date, default: Date.now },
});

const SystemSettingsSchema = new mongoose.Schema({
  ownerId: { type: String, required: true, unique: true },

  websocket: {
    enabled: { type: Boolean, default: true },
    autoReconnect: { type: Boolean, default: true },
    broadcastMode: { type: String, enum: ["all", "employees", "admins"], default: "all" },
    heartbeatIntervalSec: { type: Number, default: 30 }, // seconds
    testChannelPrefix: { type: String, default: "test" }, // prefix for test events
  },

  notifications: {
    trainingUpdates: { type: Boolean, default: true },
    employeeJoined: { type: Boolean, default: true },
    sopUpdates: { type: Boolean, default: true },
    digestMode: { type: String, enum: ["instant", "hourly", "daily"], default: "instant" },
    emailFrom: { type: String, default: "" },
  },

  workflows: {
    autoAssignOnJoin: { type: Boolean, default: true },
    autoAssignOnDeptChange: { type: Boolean, default: false },
    sopReviewCycleDays: { type: Number, default: 30 },
    inactivityDaysToFlag: { type: Number, default: 90 },
    requireApprovalForTraining: { type: Boolean, default: false },
  },

  employees: {
    selfOnboarding: { type: Boolean, default: false },
    defaultRole: { type: String, enum: ["staff", "manager"], default: "staff" },
    allowDocumentUpload: { type: Boolean, default: true },
    maxPendingSOPs: { type: Number, default: 5 },
  },

  updatedAt: { type: Date, default: Date.now },
});

const EmployeeSOPProgressSchema = new mongoose.Schema({
  employeeId: { type: String, required: true }, // firebaseUid
  sopId: { type: mongoose.Schema.Types.ObjectId, ref: "SOP", required: true },
  completed: { type: Boolean, default: false },
  completedAt: { type: Date, default: null },
  certificateUrl: { type: String, default: null },
});

const SystemSettings = mongoose.model("SystemSettings", SystemSettingsSchema);
const SystemLog = mongoose.model("SystemLog", SystemLogSchema);
const User = mongoose.model("User", UserSchema);
const Employee = mongoose.model("Employee", EmployeeSchema);
const SOP = mongoose.model("SOP", SOPSchema);
const TrainingVideo = mongoose.model("TrainingVideo", TrainingVideoSchema);
const EmployeeSOPProgress = mongoose.model("EmployeeSOPProgress", EmployeeSOPProgressSchema)

async function getEmployeeSopStats(employeeUid) {
  const total = await EmployeeSOPProgress.countDocuments({ employeeId: employeeUid });
  const completed = await EmployeeSOPProgress.countDocuments({
    employeeId: employeeUid,
    completed: true,
  });

  return {
    totalSops: total,
    completed,
    percentage: total > 0 ? Math.round((completed / total) * 100) : 0,
  };
}

// ----------------------------
// Helper: getOrCreateSettings
// ----------------------------
async function getOrCreateSettings(ownerId) {
  let settings = await SystemSettings.findOne({ ownerId });
  if (!settings) {
    settings = await SystemSettings.create({
      ownerId,
      // defaults are applied by schema
    });
    await addLog(ownerId, "Created default system settings", "settings");
    emitToOwner(ownerId, "settings:created", settings);
  }
  return settings;
}

// ----------------------------
// Routes: GET/PUT /api/settings
// and section-specific endpoints
// ----------------------------
app.get("/api/settings", authenticate, requireAdmin, async (req, res) => {
  try {
    const ownerId = req.user.firebaseUid;
    const settings = await getOrCreateSettings(ownerId);
    res.json(settings);
  } catch (err) {
    console.error("GET /api/settings error:", err);
    res.status(500).json({ message: "Failed to fetch settings" });
  }
});

app.put("/api/settings", authenticate, requireAdmin, async (req, res) => {
  try {
    const ownerId = req.user.firebaseUid;
    const incoming = req.body || {};

    const settings = await getOrCreateSettings(ownerId);

    // Merge top-level sections if present
    const merged = {
      ...settings.toObject(),
      ...incoming,
      updatedAt: new Date(),
    };

    // Avoid overwriting ownerId/_id
    delete merged._id;
    delete merged.ownerId;

    // Apply merged fields to document
    Object.keys(merged).forEach((k) => {
      settings[k] = merged[k];
    });

    await settings.save();

    await addLog(ownerId, "Updated system settings", "settings");
    emitToOwner(ownerId, "settings:updated", settings);

    res.json({ message: "Settings updated", settings });
  } catch (err) {
    console.error("PUT /api/settings error:", err);
    res.status(500).json({ message: "Failed to update settings" });
  }
});

/* Section-specific getters / updaters */
const VALID_SECTIONS = ["websocket", "notifications", "workflows", "employees"];

app.get("/api/settings/:section", authenticate, requireAdmin, async (req, res) => {
  try {
    const section = req.params.section;
    if (!VALID_SECTIONS.includes(section)) return res.status(400).json({ message: "Invalid section" });

    const settings = await getOrCreateSettings(req.user.firebaseUid);
    res.json({ [section]: settings[section] || {} });
  } catch (err) {
    console.error("GET /api/settings/:section error:", err);
    res.status(500).json({ message: "Failed to fetch section" });
  }
});

app.put("/api/settings/:section", authenticate, requireAdmin, async (req, res) => {
  try {
    const section = req.params.section;
    if (!VALID_SECTIONS.includes(section)) return res.status(400).json({ message: "Invalid section" });

    const payload = req.body || {};
    const settings = await getOrCreateSettings(req.user.firebaseUid);

    // Simple shallow merge for the section
    settings[section] = { ...(settings[section] ? settings[section].toObject ? settings[section].toObject() : settings[section] : {}), ...payload };
    settings.updatedAt = new Date();
    await settings.save();

    await addLog(req.user.firebaseUid, `Updated settings:${section}`, "settings");
    emitToOwner(req.user.firebaseUid, `settings:${section}:updated`, { section: settings[section] });

    res.json({ message: "Section updated", section: settings[section] });
  } catch (err) {
    console.error("PUT /api/settings/:section error:", err);
    res.status(500).json({ message: "Failed to update section" });
  }
});

// ----------------------------
// WebSocket test endpoint
// ----------------------------
app.post("/api/settings/ws/test", authenticate, requireAdmin, async (req, res) => {
  try {
    const ownerId = req.user.firebaseUid;
    const settings = await getOrCreateSettings(ownerId);

    // testEvent payload
    const payload = {
      ts: new Date(),
      message: req.body?.message || "WebSocket test event",
      type: "ws:test",
      settingsSnapshot: settings.websocket,
    };

    // Emits using existing helper - channels clients can subscribe to `${ownerId}:...`
    emitToOwner(ownerId, `${settings.websocket.testChannelPrefix || "test"}:event`, payload);
    await addLog(ownerId, "Sent websocket test event", "websocket");

    res.json({ message: "Test event emitted", payload });
  } catch (err) {
    console.error("POST /api/settings/ws/test error:", err);
    res.status(500).json({ message: "Failed to send test event" });
  }
});

// ----------------------------
// Convenience: apply settings on server runtime (example)
// - This demonstrates how to react to settings changes server-side.
// - Here we subscribe to change stream and log when websocket toggled.
// ----------------------------
try {
  // only if Mongo supports change streams (replica set); wrap in try/catch
  if (mongoose.connection && mongoose.connection.db) {
    const changeStream = SystemSettings.watch([], { fullDocument: "updateLookup" });
    changeStream.on("change", (change) => {
      try {
        const full = change.fullDocument;
        if (!full) return;
        // Example: log when websocket.enabled flips
        // (You can extend this to enable/disable server-side broadcast loops etc.)
        if (change.updateDescription?.updatedFields?.["websocket.enabled"] !== undefined) {
          console.log(`SystemSettings websocket.enabled changed for owner ${full.ownerId}:`, full.websocket.enabled);
          addLog(full.ownerId, `WebSocket ${full.websocket.enabled ? "enabled" : "disabled"}`, "settings").catch(() => { });
        }
      } catch (e) {
        console.error("SystemSettings change handler error:", e);
      }
    });
  }
} catch (err) {
  console.warn("SystemSettings change stream not started (not a replica set?)", err.message);
}
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
    } catch { }
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

    // FIRST try to match employee
    let emp = await Employee.findOne({ firebaseUid: decoded.user_id });

    if (emp) {
      req.user = { ...emp.toObject(), isEmployee: true };
      return next();
    }

    // otherwise match admin user
    let user = await User.findOne({ firebaseUid: decoded.user_id });

    if (!user) {
      user = await new User({
        firebaseUid: decoded.user_id,
        email: decoded.email,
      }).save();
    }

    req.user = { ...user.toObject(), isEmployee: false };
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
   LOG + WEBSOCKET BROADCAST
---------------------------------------- */
async function addLog(ownerId, message, type = "system") {
  const log = await SystemLog.create({ ownerId, message, type });
  emitToOwner(ownerId, "log:new", log);
}

/* ----------------------------------------
   CLOUDINARY SIGNATURE
---------------------------------------- */
app.get("/api/cloudinary-signature", (req, res) => {
  try {
    const timestamp = Math.round(Date.now() / 1000);
    const folder = req.query.folder || "training_videos";

    const signature = cloudinary.utils.api_sign_request(
      { timestamp, folder },
      process.env.CLOUDINARY_API_SECRET
    );

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
   🔵 REQUIRED BY YOUR FRONTEND
   GET ALL LOGS  (ActivityFeed.jsx)
---------------------------------------- */
app.get("/api/logs", authenticate, async (req, res) => {
  try {
    const logs = await SystemLog.find({ ownerId: req.user.firebaseUid })
      .sort({ createdAt: -1 })
      .limit(20);

    res.json(logs);
  } catch (err) {
    res.status(500).json({ message: "Failed to load logs" });
  }
});

/* ----------------------------------------
   🔵 REQUIRED BY YOUR FRONTEND
   GET ALL SOPs (RecentSOPs.jsx)
/* ----------------------------------------
   GET ALL SOPs
---------------------------------------- */
app.get("/api/sops", authenticate, async (req, res) => {
  try {
    const sops = await SOP.find({ ownerId: req.user.firebaseUid })
      .populate("assignedTo", "name email dept role")  // ✅ populate employees
      .sort({ updated: -1 });

    res.json(sops);
  } catch (err) {
    console.error("SOP load error:", err);
    res.status(500).json({ message: "Failed to load SOPs" });
  }
});

/* =====================================================
   CREATE SOP
   POST /api/sops
===================================================== */
app.post("/api/sops", authenticate, async (req, res) => {
  const ownerId = req.user.firebaseUid;
  const { title, dept, content, assignedTo } = req.body;

  if (!title || !dept || !content) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const sop = await SOP.create({
      ownerId,
      title,
      dept,
      content,
      assignedTo: assignedTo || [], // ✅ FIX
      createdAt: new Date(),
      updated: new Date(),
    });

    return res.json({ message: "SOP created successfully", sop });
  } catch (err) {
    console.error("CREATE SOP ERROR:", err);
    return res.status(500).json({ message: "Server error creating SOP" });
  }
});


/* =====================================================
   UPDATE / EDIT SOP
   PUT /api/sops/:id
===================================================== */
app.put("/api/sops/:id", authenticate, async (req, res) => {
  const { id } = req.params;
  const { title, dept, content, assignedTo } = req.body;

  try {
    const sop = await SOP.findById(id);
    if (!sop) return res.status(404).json({ message: "SOP not found" });

    // Update fields
    if (title) sop.title = title;
    if (dept) sop.dept = dept;
    if (content) sop.content = content;
    if (assignedTo) sop.assignedTo = assignedTo; // ✅ FIX

    sop.updated = new Date();

    await sop.save();

    return res.json({ message: "SOP updated successfully", sop });
  } catch (err) {
    console.error("UPDATE SOP ERROR:", err);
    return res.status(500).json({ message: "Server error updating SOP" });
  }
});


/* =====================================================
   GET A SINGLE SOP (View Page)
   /api/sops/:id
===================================================== */
app.get("/api/sops/:id", authenticate, async (req, res) => {
  const ownerId = req.user.firebaseUid;
  const { id } = req.params;

  try {
    const sop = await SOP.findOne({ _id: id, ownerId })
      .populate("assignedTo", "name email");

    if (!sop) {
      return res.status(404).json({ message: "SOP not found" });
    }

    res.json(sop);
  } catch (err) {
    console.error("GET SOP ERROR:", err);
    res.status(500).json({ message: "Server error loading SOP" });
  }
});



/* =====================================================
   CLEAR SOP CONTENT
   /api/sops/:id/clear
===================================================== */
app.put("/api/sops/:id/clear", authenticate, async (req, res) => {
  const ownerId = req.user.firebaseUid;
  const { id } = req.params;

  try {
    const sop = await SOP.findOne({ _id: id, ownerId });

    if (!sop) {
      return res.status(404).json({ message: "SOP not found" });
    }

    sop.content = "";
    sop.updated = new Date();

    await sop.save();

    res.json(sop);
  } catch (err) {
    console.error("CLEAR SOP ERROR:", err);
    res.status(500).json({ message: "Failed to clear SOP" });
  }
});

/* ----------------------------------------
   TRAINING ROUTES
---------------------------------------- */
app.post("/api/training", authenticate, requireAdmin, async (req, res) => {
  try {
    const { title, description, videoUrl, thumbnailUrl, assignedEmployees } =
      req.body;

    if (!title || !videoUrl)
      return res.status(400).json({ message: "Missing required fields" });

    let finalThumbnail = thumbnailUrl;
    if (!finalThumbnail)
      finalThumbnail = videoUrl.replace("/upload/", "/upload/so_1/");

    const training = await new TrainingVideo({
      ownerId: req.user.firebaseUid,
      title,
      description,
      videoUrl,
      thumbnailUrl: finalThumbnail,
      assignedEmployees: assignedEmployees || [],
    }).save();

    await addLog(req.user.firebaseUid, `Created training "${title}"`, "training");

    emitToOwner(req.user.firebaseUid, "training:created", training);

    res.json(training);
  } catch (err) {
    console.log("Training create error:", err);
    res.status(500).json({ message: "Failed to create training" });
  }
});

app.delete("/api/training/:id", authenticate, requireAdmin, async (req, res) => {
  const deleted = await TrainingVideo.findOneAndDelete({
    _id: req.params.id,
    ownerId: req.user.firebaseUid,
  });

  if (!deleted)
    return res.status(404).json({ message: "Training video not found" });

  await addLog(
    req.user.firebaseUid,
    `Deleted training "${deleted.title}"`,
    "training"
  );

  emitToOwner(req.user.firebaseUid, "training:deleted", deleted);

  res.json({ message: "Deleted" });
});

/* ----------------------------------------
   EMPLOYEE TRAINING COMPLETE
---------------------------------------- */
app.post("/api/training/:id/complete", authenticate, async (req, res) => {
  try {
    const emp = await Employee.findOne({ firebaseUid: req.user.firebaseUid });
    if (!emp) return res.status(404).json({ message: "Employee not found" });

    const training = await TrainingVideo.findById(req.params.id);
    if (!training) return res.status(404).json({ message: "Training not found" });

    if (training.ownerId !== emp.ownerId)
      return res.status(403).json({ message: "Not allowed" });

    if (
      training.assignedEmployees.length > 0 &&
      !training.assignedEmployees.includes(emp.firebaseUid)
    ) {
      return res.status(403).json({ message: "Not assigned to you" });
    }

    if (!training.completedBy.includes(emp.firebaseUid)) {
      training.completedBy.push(emp.firebaseUid);
    }

    if (training.assignedEmployees.length === 0) {
      training.status = "completed";
    } else {
      const allCompleted = training.assignedEmployees.every((uid) =>
        training.completedBy.includes(uid)
      );
      if (allCompleted) training.status = "completed";
    }

    await training.save();

    if (!emp.completedTrainings.includes(training._id)) {
      emp.completedTrainings.push(training._id);
      await emp.save();
    }

    await addLog(
      emp.ownerId,
      `${emp.name} completed training "${training.title}"`,
      "training"
    );

    emitToOwner(emp.ownerId, "training:completed", { training, employee: emp });

    res.json({ message: "Marked complete", training });
  } catch (err) {
    console.error("Mark complete error:", err);
    res.status(500).json({ message: "Failed to mark complete" });
  }
});

app.get("/api/training", authenticate, requireAdmin, async (req, res) => {
  try {
    const videos = await TrainingVideo.find({ ownerId: req.user.firebaseUid })
      .sort({ createdAt: -1 });

    res.json(videos);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch training videos" });
  }
});

/* ----------------------------------------
   EMPLOYEE: GET TRAINING LIST
   GET /api/employee/training
---------------------------------------- */
app.get("/api/employee/training", authenticate, async (req, res) => {
  try {
    const emp = await Employee.findOne({ firebaseUid: req.user.firebaseUid });
    if (!emp) return res.status(404).json({ message: "Employee not found" });

    // Fetch all trainings from the same company owner
    const allTraining = await TrainingVideo.find({ ownerId: emp.ownerId })
      .sort({ createdAt: -1 });

    // Filter → Only assigned OR global trainings
    const visibleTraining = allTraining.filter((t) => {
      return (
        t.assignedEmployees.length === 0 ||  // Global training (visible to all)
        t.assignedEmployees.includes(emp.firebaseUid) // Specifically assigned
      );
    });

    // Add completed flag
    const response = visibleTraining.map((t) => ({
      _id: t._id,
      title: t.title,
      description: t.description,
      videoUrl: t.videoUrl,
      thumbnailUrl: t.thumbnailUrl,
      assignedEmployees: t.assignedEmployees,
      completed: t.completedBy.includes(emp.firebaseUid),
      status: t.status,
      createdAt: t.createdAt,
    }));

    res.json(response);
  } catch (err) {
    console.log("Employee training list error:", err);
    res.status(500).json({ message: "Failed to load employee training" });
  }
});

// app.post("/api/training", authenticate, requireAdmin, async (req, res) => {
//   try {
//     const {
//       title,
//       description,
//       videoUrl,
//       thumbnailUrl,
//       assignedEmployees = []
//     } = req.body;

//     const newVideo = await TrainingVideo.create({
//       ownerId: req.user.firebaseUid,
//       title,
//       description,
//       videoUrl,
//       thumbnailUrl,
//       assignedEmployees,
//       status: "active",
//       completedBy: []
//     });

//     res.json(newVideo);
//   } catch (err) {
//     res.status(500).json({ message: "Failed to create training video" });
//   }
// });

app.get("/api/training/:id", authenticate, async (req, res) => {
  try {
    const video = await TrainingVideo.findOne({
      _id: req.params.id,
      ownerId: req.user.firebaseUid,
    });

    if (!video)
      return res.status(404).json({ message: "Video not found" });

    res.json(video);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch video" });
  }
});

// app.delete("/api/training/:id", authenticate, requireAdmin, async (req, res) => {
//   try {
//     const deleted = await TrainingVideo.findOneAndDelete({
//       _id: req.params.id,
//       ownerId: req.user.firebaseUid,
//     });

//     if (!deleted)
//       return res.status(404).json({ message: "Video not found" });

//     res.json({ message: "Training video deleted" });
//   } catch (err) {
//     res.status(500).json({ message: "Failed to delete video" });
//   }
// });

/* =====================================================
   GET ALL EMPLOYEES
   GET /api/employees
===================================================== */
app.get("/api/employees", authenticate, requireAdmin, async (req, res) => {
  try {
    const ownerId = req.user.firebaseUid;

    // return employees created by this owner/admin
    const employees = await Employee.find({ ownerId });

    res.json({ employees });
  } catch (err) {
    console.error("GET EMPLOYEES ERROR:", err);
    res.status(500).json({ message: "Failed to load employees" });
  }
});

// UNIVERSAL SEARCH
app.get("/api/search", authenticate, async (req, res) => {
  const q = (req.query.q || "").toLowerCase();
  const ownerId = req.user.firebaseUid;

  if (!q) return res.json({ sop: [], training: [] });

  try {
    const sops = await SOP.find({
      ownerId,
      title: { $regex: q, $options: "i" }
    }).select("title _id");

    const trainings = await TrainingVideo.find({
      ownerId,
      title: { $regex: q, $options: "i" }
    }).select("title _id thumbnailUrl");

    res.json({
      sop: sops,
      training: trainings
    });
  } catch (err) {
    res.status(500).json({ message: "Search failed" });
  }
});

/* ----------------------------------------
   EMPLOYEE CREATION
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
  } catch { }

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

  await addLog(req.user.firebaseUid, `Employee added: ${name}`, "employee");

  emitToOwner(req.user.firebaseUid, "employee:created", emp);

  res.json({ message: "Employee created", emp });
});

/* ----------------------------------------
   SOP CRUD
---------------------------------------- */
app.post("/api/sops", authenticate, requireAdmin, async (req, res) => {
  const sop = await new SOP({ ownerId: req.user.firebaseUid, ...req.body }).save();

  await addLog(req.user.firebaseUid, `Created SOP: ${sop.title}`, "sop");
  emitToOwner(req.user.firebaseUid, "sop:created", sop);

  res.json(sop);
});

app.delete("/api/sops/:id", authenticate, requireAdmin, async (req, res) => {
  const deleted = await SOP.findOneAndDelete({
    _id: req.params.id,
    ownerId: req.user.firebaseUid,
  });

  if (!deleted) return res.status(404).json({ message: "SOP not found" });

  await addLog(req.user.firebaseUid, `Deleted SOP: ${deleted.title}`, "sop");
  emitToOwner(req.user.firebaseUid, "sop:deleted", deleted);

  res.json({ message: "Deleted" });
});

/* ----------------------------------------
   STATS
---------------------------------------- */
/* ----------------------------------------
   ADMIN DASHBOARD STATS
---------------------------------------- */
app.get("/api/stats", authenticate, requireAdmin, async (req, res) => {
  try {
    const ownerId = req.user.firebaseUid;

    // EMPLOYEES
    const employees = await Employee.countDocuments({ ownerId });

    // TRAININGS
    const activeTrainings = await TrainingVideo.countDocuments({
      ownerId,
      status: "active",
    });

    const completedTrainings = await TrainingVideo.countDocuments({
      ownerId,
      status: "completed",
    });

    // SOP TOTALS
    const totalSops = await SOP.countDocuments({ ownerId });

    // COMPLETED SOPs by employees
    const completedSOPs = await EmployeeSOPProgress.countDocuments({
      ownerId,
      completed: true,
    });

    // Remaining SOPs
    const pendingSOPs =
      totalSops - completedSOPs < 0 ? 0 : totalSops - completedSOPs;

    res.json({
      employees,
      activeTrainings,
      completedTrainings,
      completedSOPs,
      pendingSOPs,
    });
  } catch (err) {
    console.error("Stats error:", err);
    res.status(500).json({ message: "Failed to fetch stats" });
  }
});

app.get("/api/users/me", authenticate, async (req, res) => {
  const user = await User.findOne({ firebaseUid: req.user.firebaseUid });
  if (!user) return res.status(404).json({ message: "User not found" });

  return res.json(user);
});

app.get("/api/employees/me", authenticate, async (req, res) => {
  const emp = await Employee.findOne({ firebaseUid: req.user.firebaseUid });
  if (!emp) return res.status(404).json({ message: "Employee not found" });

  return res.json(emp);
});

/* ----------------------------------------
   GET ALL EMPLOYEES (OWNER ONLY)
---------------------------------------- */
app.get("/api/employees", authenticate, requireAdmin, async (req, res) => {
  try {
    const employees = await Employee.find({ ownerId: req.user.firebaseUid });
    res.json(employees);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch employees" });
  }
});



// GET /api/sops/:id/progress
app.get("/api/sops/:id/progress", authenticate, async (req, res) => {
  const employeeId = req.user.firebaseUid;

  const progress = await EmployeeSOPProgress.findOne({
    employeeId,
    sopId: req.params.id,
  });

  res.json(progress || { completed: false });
});

// GET /api/admin/sops/completed-count
app.get("/api/admin/sops/completed-count", authenticate, async (req, res) => {
  const total = await EmployeeSOPProgress.countDocuments({ completed: true });
  res.json({ total });
});

/* =====================================================
   EMPLOYEE — MARK SOP COMPLETE
   POST /api/employee/sops/:id/complete
===================================================== */
app.post("/api/employee/sops/:id/complete", authenticate, async (req, res) => {
  try {
    if (!req.user.isEmployee)
      return res.status(403).json({ message: "Employees only" });

    const empUid = req.user.firebaseUid;
    const { id } = req.params;

    // Check SOP exists & employee allowed
    const sop = await SOP.findById(id);
    if (!sop) return res.status(404).json({ message: "SOP not found" });

    // Find or create progress document
    let progress = await EmployeeSOPProgress.findOne({
      employeeId: empUid,
      sopId: id,
    });

    if (!progress) {
      progress = await EmployeeSOPProgress.create({
        employeeId: empUid,
        sopId: id,
        completed: false,
      });
    }

    // If already completed → no need to duplicate
    if (progress.completed) {
      return res.json({
        progress,
        stats: await getEmployeeSopStats(empUid),
      });
    }

    // Generate certificate PDF
    const certificateUrl = await generateCertificate({
      employeeName: req.user.name,
      sopTitle: sop.title,
    });

    progress.completed = true;
    progress.completedAt = new Date();
    progress.certificateUrl = certificateUrl;
    await progress.save();

    // Return updated stats for progress bar
    const stats = await getEmployeeSopStats(empUid);

    return res.json({ message: "SOP completed", progress, stats });
  } catch (err) {
    console.error("SOP COMPLETE ERROR:", err);
    return res.status(500).json({ message: "Failed to mark complete" });
  }
});

/* =====================================================
   EMPLOYEE — GET ASSIGNED SOPs
   /api/employee/sops
===================================================== */
app.get("/api/employee/sops", authenticate, async (req, res) => {
  try {
    // must be employee only
    if (!req.user.isEmployee) {
      return res.status(403).json({ message: "Employees only" });
    }

    // find this employee
    const emp = await Employee.findOne({ firebaseUid: req.user.firebaseUid });
    if (!emp) return res.status(404).json({ message: "Employee not found" });

    // get SOPs where this employee is assigned
    const sops = await SOP.find({
      ownerId: emp.ownerId,
      assignedTo: emp._id,       // 👈 the IMPORTANT FILTER
    }).sort({ updated: -1 });

    res.json(sops);
  } catch (err) {
    console.error("EMPLOYEE SOP LOAD ERROR:", err);
    res.status(500).json({ message: "Failed to load employee SOPs" });
  }
});

/* =====================================================
   EMPLOYEE — MARK SOP COMPLETED
   /api/employee/sops/:id/complete
===================================================== */
app.post("/api/employee/sops/:id/complete", authenticate, async (req, res) => {
  try {
    if (!req.user.isEmployee)
      return res.status(403).json({ message: "Employees only" });

    const sopId = req.params.id;

    const emp = await Employee.findOne({ firebaseUid: req.user.firebaseUid });
    if (!emp) return res.status(404).json({ message: "Employee not found" });

    const sop = await SOP.findById(sopId);
    if (!sop) return res.status(404).json({ message: "SOP not found" });

    // Prevent multiple completion entries
    const alreadyDone = sop.completedBy.some(
      (x) => x.empId.toString() === emp._id.toString()
    );

    if (alreadyDone) {
      return res.json({ message: "Already completed" });
    }

    sop.completedBy.push({
      empId: emp._id,
      completedAt: new Date(),
    });

    await sop.save();

    res.json({ message: "SOP marked as completed" });
  } catch (err) {
    console.error("SOP COMPLETE ERROR:", err);
    res.status(500).json({ message: "Server error completing SOP" });
  }
});

/* ----------------------------------------
   DELETE EMPLOYEE
---------------------------------------- */
app.delete("/api/employees/:id", authenticate, requireAdmin, async (req, res) => {
  try {
    const deleted = await Employee.findOneAndDelete({
      _id: req.params.id,
      ownerId: req.user.firebaseUid,
    });

    if (!deleted)
      return res.status(404).json({ message: "Employee not found" });

    await addLog(
      req.user.firebaseUid,
      `Employee deleted: ${deleted.name}`,
      "employee"
    );

    emitToOwner(req.user.firebaseUid, "employee:deleted", deleted);

    res.json({ message: "Employee deleted" });
  } catch (err) {
    console.error("Employee delete error:", err);
    res.status(500).json({ message: "Failed to delete employee" });
  }
});

/* =====================================================
   EMPLOYEE – MARK SOP COMPLETED
   POST /api/sops/:id/complete
===================================================== */
app.post("/api/sops/:id/complete", authenticate, async (req, res) => {
  try {
    const employeeUid = req.user.firebaseUid;
    const sopId = req.params.id;

    const emp = await Employee.findOne({ firebaseUid: employeeUid });
    if (!emp) return res.status(404).json({ message: "Employee not found" });

    const sop = await SOP.findById(sopId);
    if (!sop) return res.status(404).json({ message: "SOP not found" });

    if (sop.ownerId !== emp.ownerId)
      return res.status(403).json({ message: "Not allowed" });

    // --------- Check if already completed ----------
    let progress = await EmployeeSOPProgress.findOne({
      employeeId: employeeUid,
      sopId
    });

    if (progress && progress.completed)
      return res.json({ message: "Already completed", progress });

    // If no progress exists, create it
    if (!progress) {
      progress = await EmployeeSOPProgress.create({
        employeeId: employeeUid,
        sopId
      });
    }

    // --------- Mark Completed ----------
    progress.completed = true;
    progress.completedAt = new Date();

    // Generate certificate PDF and upload it
    const certificateUrl = await generateCertificate({
      employeeName: emp.name,
      sopTitle: sop.title,
    });

    progress.certificateUrl = certificateUrl;
    await progress.save();

    // --------- Update Employee Stats ----------
    emp.completedBy.push({
      empId: emp._id,
      completedAt: new Date()
    });

    if (emp.pendingSOPs > 0) emp.pendingSOPs -= 1;

    await emp.save();

    // --------- LOG + SOCKET ----------
    await addLog(
      emp.ownerId,
      `${emp.name} completed SOP "${sop.title}"`,
      "sop"
    );

    emitToOwner(emp.ownerId, "sop:completed", {
      employee: emp.name,
      sopId,
      sopTitle: sop.title,
      certificateUrl
    });

    res.json({
      message: "SOP marked as completed",
      progress,
      certificateUrl
    });

  } catch (err) {
    console.error("SOP COMPLETE ERROR:", err);
    res.status(500).json({ message: "Failed to mark SOP as completed" });
  }
});

app.get("/api/employee/sops/:id", authenticate, async (req, res) => {
  try {
    if (!req.user.isEmployee)
      return res.status(403).json({ message: "Employees only" });

    const sopId = req.params.id;

    const emp = await Employee.findOne({ firebaseUid: req.user.firebaseUid });
    if (!emp) return res.status(404).json({ message: "Employee not found" });

    const sop = await SOP.findOne({
      _id: sopId,
      assignedTo: emp._id,
    }).lean();

    if (!sop) return res.status(404).json({ message: "SOP not found" });

    sop.completed =
      sop.completedBy?.some(
        (x) => x.empId.toString() === emp._id.toString()
      ) || false;

    res.json(sop);
  } catch (err) {
    console.error("LOAD EMP SOP ERROR:", err);
    res.status(500).json({ message: "Error loading SOP" });
  }
});

// GET /api/employees/me/sop-progress
app.get("/api/employees/me/sop-progress", authenticate, async (req, res) => {
  const employeeId = req.user.firebaseUid;

  const totalSops = await SOP.countDocuments();
  const completed = await EmployeeSOPProgress.countDocuments({
    employeeId,
    completed: true,
  });

  res.json({
    totalSops,
    completed,
    percentage: totalSops === 0 ? 0 : Math.round((completed / totalSops) * 100),
  });
});

/* ----------------------------------------
   START SERVER
---------------------------------------- */
const PORT = process.env.PORT || 5000;
server.listen(PORT, () =>
  console.log("🚀 Server + WebSocket running on " + PORT)
);
