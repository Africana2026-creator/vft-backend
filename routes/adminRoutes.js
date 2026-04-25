import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import Admin from "../models/Admin.js";
import { protectAdmin } from "../middleware/authMiddleware.js";
import Booking from "../models/Booking.js";

const router = express.Router();

router.get("/test", (req, res) => {
  res.json({ message: "ADMIN ROUTES WORKING" });
});

/* =========================
   ADMIN LOGIN (FIXED)
========================= */
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    const admin = await Admin.findOne({
      email: email.toLowerCase().trim()
    });

    if (!admin) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      {
        id: admin._id,
        email: admin.email
      },
      process.env.JWT_SECRET,
      {
        expiresIn: process.env.JWT_EXPIRES_IN || "1d"
      }
    );

    res.json({
      message: "Login successful",
      token
    });

  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});


/* =========================
   ONE-TIME ADMIN SETUP
   (MAX 3 ADMINS TOTAL)
========================= */
router.post("/setup", async (req, res) => {
  try {
    console.log("🟢 SETUP ROUTE HIT");
    console.log("BODY:", req.body);

    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // 🔢 Count existing admins
    const adminCount = await Admin.countDocuments();
    console.log("ADMIN COUNT:", adminCount);

    // 🔐 Allow ONLY 3 admins total
    if (adminCount >= 3) {
      return res.status(403).json({
        message: "Admin limit reached. No more admins can be created."
      });
    }

    // 🚫 Prevent duplicate email or username
    const existingAdmin = await Admin.findOne({
      $or: [
        { email: email.toLowerCase().trim() },
        { username: username.trim() }
      ]
    });

    if (existingAdmin) {
      return res.status(409).json({
        message: "Admin with this email or username already exists"
      });
    }

    // 🔐 Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // ✅ Create admin
    const admin = await Admin.create({
      username: username.trim(),
      email: email.toLowerCase().trim(),
      password: hashedPassword
    });

    console.log("✅ ADMIN CREATED:", admin.username);

    res.json({
      message: `Admin created successfully (${adminCount + 1}/3)`
    });

  } catch (err) {
    console.error("❌ SETUP ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});
/* =========================
   CHECK IF ADMIN EXISTS
========================= */
router.get("/exists", async (req, res) => {
  const count = await Admin.countDocuments();
  res.json({ exists: count > 0 });
});

/* =========================
   PROTECTED ROUTES
========================= */
router.get("/bookings", protectAdmin, async (req, res) => {
  const bookings = await Booking.find().sort({ createdAt: -1 });
  res.json(bookings);
});

router.delete("/bookings/:id", protectAdmin, async (req, res) => {
  await Booking.findByIdAndDelete(req.params.id);
  res.json({ message: "Booking deleted successfully" });
});
// =========================
// EMAIL RECEIPT (ADMIN)
// =========================
import generateReceipt from "../utils/generateReceipt.js";
import sendEmail from "../utils/sendEmail.js";

router.post("/bookings/:id/email-receipt", protectAdmin, async (req, res) => {
  try {
    const booking = await Booking.findById(req.params.id);

    if (!booking) {
      return res.status(404).json({ message: "Booking not found" });
    }

    const pdfPath = await generateReceipt(booking);

    await sendEmail({
      to: booking.email,
      subject: "Booking Receipt – Victoria Falls Transporters",
      html: `
        <h3>Booking Receipt</h3>
        <p>Booking Ref: <b>${booking.bookingRef}</b></p>
        <p>Total: <b>$${booking.totalPrice}</b></p>
      `,
      attachmentPath: pdfPath
    });

    res.json({ message: "Receipt emailed successfully" });

  } catch (err) {
    console.error("EMAIL RECEIPT ERROR:", err);
    res.status(500).json({ message: "Failed to email receipt" });
  }
});

// =========================
// PRINT / DOWNLOAD RECEIPT
// =========================
import fs from "fs";

router.get("/bookings/:id/receipt", protectAdmin, async (req, res) => {
  try {
    const booking = await Booking.findById(req.params.id);

    if (!booking) {
      return res.status(404).json({ message: "Booking not found" });
    }

    const pdfPath = await generateReceipt(booking);

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename=receipt-${booking.bookingRef}.pdf`
    );

    fs.createReadStream(pdfPath).pipe(res);

  } catch (err) {
    console.error("PRINT RECEIPT ERROR:", err);
    res.status(500).json({ message: "Failed to generate receipt" });
  }
});

export default router;