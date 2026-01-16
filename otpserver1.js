/**
 * Twilio OTP Server (Vercel-safe)
 * Uses Firestore instead of in-memory Map
 */

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const axios = require("axios"); // kept (not removed)
const admin = require("firebase-admin");
const twilio = require("twilio");

const app = express();
require("dotenv").config();

app.use(cors());
app.use(express.json());

// ================= CONFIG =================
const PORT = 4000;

const {
  FAST2SMS_API_KEY, // kept as-is
  FIREBASE_PROJECT_ID,
  FIREBASE_CLIENT_EMAIL,
  FIREBASE_PRIVATE_KEY,

  // 🔹 TWILIO
  TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN,
  TWILIO_PHONE_NUMBER,
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

// ================= INIT TWILIO =================
const twilioClient = twilio(
  TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN
);

// ================= UTILITIES =================
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function hashOTP(otp) {
  return crypto.createHash("sha256").update(otp).digest("hex");
}
// =============================================
app.get("/", (req, res) => {
  res.send("Server awake");
});

// ================= SEND OTP =================
app.post("/send-otp", async (req, res) => {
  try {
    console.log("REQUEST BODY:", req.body);
    let { phone } = req.body;

    if (!phone) {
      return res
        .status(400)
        .json({ success: false, message: "phone is required" });
    }

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

    // ================= TWILIO OTP SEND =================
    await twilioClient.messages.create({
      body: `Your OTP is ${otp}. It will expire in 5 minutes.`,
      from: TWILIO_PHONE_NUMBER,
      to: `+91${phone}`,
    });

    return res.json({
      success: true,
      message: "OTP sent successfully",
    });
  } catch (err) {
    console.error("SEND OTP ERROR:", err.message);
    return res.status(500).json({
      success: false,
      message: "Failed to send OTP",
    });
  }
});

// ================= VERIFY OTP =================
app.post("/verify-otp", async (req, res) => {
  try {
    console.log("REQUEST BODY:", req.body);
    const { phone, otp } = req.body;

    if (!phone || !otp) {
      return res.status(400).json({
        success: false,
        message: "phone and otp are required",
      });
    }

    const cleanPhone = phone.replace(/\D/g, "").slice(-10);
    const ref = db.collection("otp_requests").doc(cleanPhone);
    const snap = await ref.get();

    if (!snap.exists) {
      return res.status(400).json({
        success: false,
        message: "OTP not found or already used",
      });
    }

    const data = snap.data();

    if (Date.now() > data.expiresAt) {
      await ref.delete();
      return res.status(400).json({
        success: false,
        message: "OTP expired",
      });
    }

    if (hashOTP(otp) !== data.otpHash) {
      return res.status(400).json({
        success: false,
        message: "Invalid OTP",
      });
    }

    return res.json({
      success: true,
      verified: true,
    });
  } catch (err) {
    console.error("VERIFY OTP ERROR:", err.message);
    return res.status(500).json({
      success: false,
      message: "Verification failed",
    });
  }
});

// ================= RESET PASSWORD =================
app.post("/reset-password", async (req, res) => {
    console.log("REQUEST BODY:", req.body);
  try {
    const { phone, otp, newPassword } = req.body;

    if (!phone || !otp || !newPassword) {
      return res.status(400).json({
        success: false,
        message: "phone, otp and newPassword are required",
      });
    }

    const cleanPhone = phone.replace(/\D/g, "").slice(-10);
    const ref = db.collection("otp_requests").doc(cleanPhone);
    const snap = await ref.get();

    if (!snap.exists) {
      return res.status(400).json({
        success: false,
        message: "OTP not found or already used",
      });
    }

    const data = snap.data();

    if (Date.now() > data.expiresAt) {
      await ref.delete();
      return res.status(400).json({
        success: false,
        message: "OTP expired",
      });
    }

    if (hashOTP(otp) !== data.otpHash) {
      return res.status(400).json({
        success: false,
        message: "Invalid OTP",
      });
    }

    await ref.delete();

    const email = `${cleanPhone}@userapp.com`;

    try {
      const user = await admin.auth().getUserByEmail(email);
      await admin.auth().updateUser(user.uid, {
        password: String(newPassword),
      });
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

    return res.json({
      success: true,
      message: "Password updated",
    });
  } catch (err) {
    console.error("RESET PASSWORD ERROR:", err.message);
    return res.status(500).json({
      success: false,
      message: "Password reset failed",
    });
  }
});


app.get("/cleargameresult", async (req, res) => {
  try {
    // -----------------------------
    // 1. Get current IST time
    // -----------------------------
    const nowIst = new Date(
      new Date().toLocaleString("en-US", { timeZone: "Asia/Kolkata" })
    );

    const hours = nowIst.getHours();     // 0–23
    const minutes = nowIst.getMinutes(); // 0–59
    const currentMinutes = hours * 60 + minutes;

    // -----------------------------
    // 2. Allowed window
    //    04:45 AM → 05:15 AM IST
    // -----------------------------
    const startWindow = 4 * 60 + 45; // 285
    const endWindow = 5 * 60 + 15;   // 315

    // if (currentMinutes < startWindow || currentMinutes > endWindow) {
    //   return res.status(413).json({
    //     success: false,
    //     message: "cleargameresult can only run between 04:45 AM and 05:15 AM IST",
    //     currentTimeIST: nowIst.toTimeString().slice(0, 5),
    //   });
    // }

    // -----------------------------
    // 3. Clear games collection
    // -----------------------------
    const gamesCol = db.collection("games");
    const snap = await gamesCol.get();

    if (snap.empty) {
      return res.status(200).json({
        success: true,
        processed: 0,
        message: "No games found",
      });
    }

    const BATCH_LIMIT = 500;
    let batch = db.batch();
    let opCount = 0;
    let total = 0;

    for (const doc of snap.docs) {
      const data = doc.data() || {};
      const ref = gamesCol.doc(doc.id);

      const payload = {
        chartLink: data.chartLink ?? null,
        createdAt: data.createdAt ?? null,
        gameId: doc.id,
        name: data.name ?? doc.id,
        result: "***-**-***",
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        clear_result: true,
        openTime: data.openTime ?? null,
        closeTime: data.closeTime ?? null,
      };

      batch.set(ref, payload, { merge: false });
      opCount++;
      total++;

      if (opCount >= BATCH_LIMIT) {
        await batch.commit();
        batch = db.batch();
        opCount = 0;
      }
    }

    if (opCount > 0) {
      await batch.commit();
    }

    console.log(`cleargameresult: processed ${total} game docs`);

    return res.status(200).json({
      success: true,
      processed: total,
      ranAtIST: nowIst.toTimeString().slice(0, 5),
    });
  } catch (err) {
    console.error("cleargameresult failed:", err);
    return res.status(500).json({
      success: false,
      message: "Failed to clear game results",
    });
  }
});

// ================= START SERVER =================
app.listen(PORT, "0.0.0.0", () => {
  console.log(`OTP server running on port clear game ${PORT}`);
});
