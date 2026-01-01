/**
 * Fast2SMS OTP Server (Vercel-safe)
 * Uses Firestore instead of in-memory Map
 */

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const axios = require("axios");
const admin = require("firebase-admin");

const app = express();
require("dotenv").config();

app.use(cors());
app.use(express.json());

// ================= CONFIG =================
const PORT = 4000;

const {
  FAST2SMS_API_KEY,
  FIREBASE_PROJECT_ID,
  FIREBASE_CLIENT_EMAIL,
  FIREBASE_PRIVATE_KEY,
} = process.env;

const OTP_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes
// =========================================

// ================= INIT FIREBASE ADMIN =================
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: FIREBASE_PROJECT_ID,
      clientEmail: FIREBASE_CLIENT_EMAIL,
      privateKey: FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    }),
  });
}

const db = admin.firestore();

// ================= UTILITIES =================
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function hashOTP(otp) {
  return crypto.createHash("sha256").update(otp).digest("hex");
}
// =============================================

// ================= SEND OTP =================
app.post("/send-otp", async (req, res) => {
  try {
    let { phone } = req.body;
    if (!phone) {
      return res.status(400).json({ success: false, message: "phone is required" });
    }
console.log(FAST2SMS_API_KEY);
    // ✅ Convert +91XXXXXXXXXX → XXXXXXXXXX
    phone = phone.replace(/\D/g, "").slice(-10);

    const otp = generateOTP();
    const otpHash = hashOTP(otp);
    const expiresAt = Date.now() + OTP_EXPIRY_MS;

    // Store OTP in Firestore
    await db.collection("otp_requests").doc(phone).set({
      otpHash,
      expiresAt,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // 🔥 FAST2SMS OTP API
    await axios.get("https://www.fast2sms.com/dev/bulkV2", {
      headers: {
        authorization: FAST2SMS_API_KEY,
      },
      params: {
        route: "otp",
        variables_values: otp,
        numbers: phone,
      },
    });

    return res.json({ success: true, message: "OTP sent successfully" });
  } catch (err) {
    console.error("SEND OTP ERROR:", err.message);
    return res.status(500).json({ success: false, message: "Failed to send OTP" });
  }
});

// ================= VERIFY OTP =================
app.post("/verify-otp", async (req, res) => {
  try {
    const { phone, otp } = req.body;
    if (!phone || !otp) {
      return res.status(400).json({ success: false, message: "phone and otp are required" });
    }

    const cleanPhone = phone.replace(/\D/g, "").slice(-10);
    const ref = db.collection("otp_requests").doc(cleanPhone);
    const snap = await ref.get();

    if (!snap.exists) {
      return res.status(400).json({ success: false, message: "OTP not found or already used" });
    }

    const data = snap.data();
    if (Date.now() > data.expiresAt) {
      await ref.delete();
      return res.status(400).json({ success: false, message: "OTP expired" });
    }

    if (hashOTP(otp) !== data.otpHash) {
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    }

    return res.json({ success: true, verified: true });
  } catch (err) {
    console.error("VERIFY OTP ERROR:", err.message);
    return res.status(500).json({ success: false, message: "Verification failed" });
  }
});

// ================= RESET PASSWORD =================
app.post("/reset-password", async (req, res) => {
  try {
    const { phone, otp, newPassword } = req.body;
    if (!phone || !otp || !newPassword) {
      return res.status(400).json({ success: false, message: "phone, otp and newPassword are required" });
    }

    const cleanPhone = phone.replace(/\D/g, "").slice(-10);
    const ref = db.collection("otp_requests").doc(cleanPhone);
    const snap = await ref.get();
    if (!snap.exists) return res.status(400).json({ success: false, message: "OTP not found or already used" });

    const data = snap.data();
    if (Date.now() > data.expiresAt) {
      await ref.delete();
      return res.status(400).json({ success: false, message: "OTP expired" });
    }

    if (hashOTP(otp) !== data.otpHash) {
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    }

    await ref.delete();

    const email = `${cleanPhone}@userapp.com`;

    try {
      const user = await admin.auth().getUserByEmail(email);
      await admin.auth().updateUser(user.uid, { password: String(newPassword) });
    } catch (e) {
      if (e.code === "auth/user-not-found") {
        await admin.auth().createUser({
          email,
          phoneNumber: `+91${cleanPhone}`,
          password: String(newPassword),
        });
      } else {
        throw e;
      }
    }

    return res.json({ success: true, message: "Password updated" });
  } catch (err) {
    console.error("RESET PASSWORD ERROR:", err.message);
    return res.status(500).json({ success: false, message: "Password reset failed" });
  }
});

// ================= START SERVER =================
app.listen(PORT, "0.0.0.0", () => {
  console.log(`OTP server running on port ${PORT}`);
});
