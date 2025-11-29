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

dotenv.config();

/*
  Required ENV (minimum):
  - MONGO_URI
  - FIREBASE_PROJECT_ID
  - CF_APP_ID
  - CF_SECRET
  - (optional) FIREBASE_ADMIN_CERT or GOOGLE_APPLICATION_CREDENTIALS
  - (optional) SERVER_URL
  - PORT
*/

if (!process.env.MONGO_URI) {
  console.error("Missing MONGO_URI in environment - exiting.");
  process.exit(1);
}
if (!process.env.FIREBASE_PROJECT_ID) {
  console.error("Missing FIREBASE_PROJECT_ID in environment - exiting.");
  process.exit(1);
}
if (!process.env.CF_APP_ID || !process.env.CF_SECRET) {
  console.error("Missing CF_APP_ID or CF_SECRET in environment - exiting.");
  process.exit(1);
}

const CF_CLIENT_ID = process.env.CF_APP_ID;
const CF_CLIENT_SECRET = process.env.CF_SECRET;
const CF_ENDPOINT = "https://api.cashfree.com/pg/orders"; // PRODUCTION

// ------------ Optional firebase-admin init ------------
let firebaseAdminInitialized = false;

try {
    const serviceAccount = JSON.parse(process.env.FIREBASE_ADMIN_CERT);

    if (!admin.apps.length) {
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount),
        });
    }

    firebaseAdminInitialized = true;
    console.log("✅ Firebase Admin initialized");
} catch (err) {
    console.log("ℹ️ firebase-admin not initialized (service account missing)");
}


// ------------ Firebase token verification (JWKS) ------------
const jwksUri =
  "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";

const client = jwksClient({
  jwksUri,
  timeout: 30000,
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

function verifyFirebaseToken(idToken) {
  return new Promise((resolve, reject) => {
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

// ------------ App init ------------
const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));

// ------------ Mongo connect ------------
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => {
    console.error("Mongo error:", err);
    process.exit(1);
  });

// ------------ Models ------------
const UserSchema = new mongoose.Schema({
  firebaseUid: { type: String, required: true, unique: true },
  email: { type: String, required: true },
  role: { type: String, enum: ["admin", "staff"], default: "staff" },
  createdAt: { type: Date, default: Date.now },
});

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
  role: { type: String, enum: ["owner", "manager", "staff"], default: "staff" },
  status: { type: String, enum: ["active", "inactive"], default: "active" },
  createdAt: { type: Date, default: Date.now },
});

const SubscriptionSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  planId: { type: String, required: true },
  status: { type: String, enum: ["active", "expired", "cancelled"], default: "active" },
  startDate: { type: Date, default: Date.now },
  endDate: { type: Date, required: true },
  orderId: { type: String },
});

const User = mongoose.model("User", UserSchema);
const SOP = mongoose.model("SOP", SOPSchema);
const Employee = mongoose.model("Employee", EmployeeSchema);
const Subscription = mongoose.model("Subscription", SubscriptionSchema);

// ------------ Keep alive ------------
app.get("/ping", (req, res) => res.json({ status: "active", time: new Date() }));

if (process.env.SERVER_URL) {
  cron.schedule("*/14 * * * *", async () => {
    try {
      console.log("Ping...");
      await fetch(process.env.SERVER_URL + "/ping");
    } catch { }
  });
}

// ------------ Auth middleware ------------
async function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer "))
    return res.status(401).json({ message: "Missing token" });

  const token = header.split(" ")[1];

  try {
    const decoded = await verifyFirebaseToken(token);
    const uid = decoded.user_id ?? decoded.sub;
    const email = decoded.email;

    let dbUser = await User.findOne({ firebaseUid: uid });
    if (!dbUser) {
      dbUser = new User({ firebaseUid: uid, email });
      await dbUser.save();
    }

    req.user = { uid, email, role: dbUser.role };
    next();
  } catch (e) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

const requireAdmin = (req, res, next) =>
  req.user?.role === "admin"
    ? next()
    : res.status(403).json({ message: "Admin only" });

// ----------------------------------------------
// PAYMENT: OPTION A (Create order → Payment link)
// ----------------------------------------------
app.post("/create-payment-link", async (req, res) => {
  const { amount, customerId, customerEmail, customerPhone } = req.body;

  const payload = {
    order_id: "order_" + Date.now(),
    order_amount: amount,
    order_currency: "INR",
    customer_details: {
      customer_id: customerId,
      customer_email: customerEmail,
      customer_phone: customerPhone,
    },
    order_meta: {
      return_url: "https://train-desk.vercel.app/payment-success?order_id={order_id}"
    }
  };

  const response = await fetch("https://api.cashfree.com/pg/orders", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-client-id": process.env.CF_CLIENT_ID,
      "x-client-secret": process.env.CF_CLIENT_SECRET,
      "x-api-version": "2022-09-01",
    },
    body: JSON.stringify(payload)
  });

  const data = await response.json();
  res.json(data);
});

app.get("/api/employees/me", authenticate, async (req, res) => {
  const emp = await Employee.findOne({ firebaseUid: req.user.uid });
  if (!emp) return res.status(404).json({ message: "Not employee" });
  res.json(emp);
});


// ------------ USERS ------------
app.post("/api/users/register-admin", authenticate, async (req, res) => {
  try {
    const user = await User.findOneAndUpdate(
      { firebaseUid: req.user.uid },
      { role: "admin" },
      { new: true }
    );
    res.json({ message: "Registered admin", user });
  } catch {
    res.status(500).json({ message: "Error" });
  }
});

app.get("/api/users/me", authenticate, async (req, res) => {
  try {
    const user = await User.findOne({ firebaseUid: req.user.uid });
    res.json(user);
  } catch {
    res.status(500).json({ message: "Error" });
  }
});

// ------------ EMPLOYEES ------------
app.post("/api/employees", authenticate, requireAdmin, async (req, res) => {
  try {
    const { name, email, dept, role = "staff", status = "active" } = req.body;

    if (!name || !email || !dept)
      return res.status(400).json({ message: "Missing fields" });

    let firebaseUid = null;

    if (firebaseAdminInitialized) {
      let user = null;
      try {
        user = await admin.auth().getUserByEmail(email);
      } catch { }

      if (!user) {
        const tempPassword = Math.random().toString(36).slice(-10) + "Aa1!";
        user = await admin.auth().createUser({ email, password: tempPassword });
      }

      firebaseUid = user.uid;
    } else {
      const existing = await User.findOne({ email });
      if (!existing)
        return res.status(400).json({
          message:
            "Firebase-admin not initialized. Create this user in Firebase first.",
        });

      firebaseUid = existing.firebaseUid;
    }

    const emp = new Employee({
      ownerId: req.user.uid,
      firebaseUid,
      name,
      email,
      dept,
      role,
      status,
    });

    await emp.save();
    res.json({ message: "Employee added", emp });
  } catch (err) {
    res.status(500).json({ message: "Error" });
  }
});

app.get("/api/employees", authenticate, requireAdmin, async (req, res) => {
  const list = await Employee.find({ ownerId: req.user.uid }).sort({ createdAt: -1 });
  res.json(list);
});

// ------------ SOP CRUD ------------
app.post("/api/sops", authenticate, requireAdmin, async (req, res) => {
  const { title, dept, content } = req.body;
  const sop = new SOP({ title, dept, content, ownerId: req.user.uid });
  await sop.save();
  res.json({ message: "Created", sop });
});

app.delete("/api/sops/:id", authenticate, requireAdmin, async (req, res) => {
  try {
    const deleted = await SOP.findOneAndDelete({
      _id: req.params.id,
      ownerId: req.user.uid,
    });

    if (!deleted) return res.status(404).json({ message: "Not found" });

    res.json({ message: "Deleted" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


app.get("/api/sops", authenticate, requireAdmin, async (req, res) => {
  const sops = await SOP.find({ ownerId: req.user.uid }).sort({ updated: -1 });
  res.json(sops);
});

// ------------ Stats ------------
app.get("/api/stats", authenticate, requireAdmin, async (req, res) => {
  const employees = await Employee.countDocuments({ ownerId: req.user.uid });
  const sops = await SOP.countDocuments({ ownerId: req.user.uid });
  res.json({ employees, activeTrainings: 0, completedTrainings: 0, pendingSOPs: sops });
});

// ------------ Start server ------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
