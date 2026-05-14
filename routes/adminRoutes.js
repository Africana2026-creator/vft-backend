import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import fs from "fs";

import Admin from "../models/Admin.js";
import Booking from "../models/Booking.js";

import protectAdmin from "../middleware/authMiddleware.js";
import generateReceipt from "../utils/generateReceipt.js";
import generateReceiptBuffer from "../utils/generateReceiptBuffer.js";
import sendReceiptEmail from "../utils/sendReceiptEmail.js";

const router = express.Router();

/* =========================
   TEST ROUTE
========================= */
router.get("/test", (req, res) => {
  res.json({ message: "ADMIN ROUTES WORKING" });
});

/* =========================
   ADMIN LOGIN
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
      { id: admin._id, email: admin.email },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || "1d" }
    );

    res.json({ message: "Login successful", token });

  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   ONE-TIME ADMIN SETUP
   (MAX 3 ADMINS)
========================= */
router.post("/setup", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const adminCount = await Admin.countDocuments();
    if (adminCount >= 3) {
      return res.status(403).json({
        message: "Admin limit reached. No more admins allowed."
      });
    }

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

    const hashedPassword = await bcrypt.hash(password, 12);

    await Admin.create({
      username: username.trim(),
      email: email.toLowerCase().trim(),
      password: hashedPassword
    });

    res.json({
      message: `Admin created successfully (${adminCount + 1}/3)`
    });

  } catch (err) {
    console.error("SETUP ERROR:", err);
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
   GET ALL BOOKINGS (ADMIN)
========================= */
router.get("/bookings", protectAdmin, async (req, res) => {
  try {
    const bookings = await Booking.find().sort({ createdAt: -1 });
    res.json(bookings);
  } catch (err) {
    console.error("FETCH BOOKINGS ERROR:", err);
    res.status(500).json({ message: "Failed to fetch bookings" });
  }
});

/* =========================
   DELETE BOOKING
========================= */
router.delete("/bookings/:id", protectAdmin, async (req, res) => {
  try {
    const booking = await Booking.findByIdAndDelete(req.params.id);

    if (!booking) {
      return res.status(404).json({ message: "Booking not found" });
    }

    res.json({ message: "Booking deleted successfully" });
  } catch (err) {
    console.error("DELETE BOOKING ERROR:", err);
    res.status(500).json({ message: "Failed to delete booking" });
  }
});

/* =========================
   EMAIL RECEIPT (ADMIN)
========================= */
router.post("/bookings/:id/email-receipt", protectAdmin, async (req, res) => {
  try {
    const booking = await Booking.findById(req.params.id);

    if (!booking || !booking.email) {
      return res.status(404).json({ message: "Booking or email not found" });
    }

    const pdfBuffer = await generateReceiptBuffer(booking);

    await sendReceiptEmail(
      booking.email.trim(),
      pdfBuffer,
      booking.bookingRef
    );

    res.json({ message: "Receipt emailed successfully" });

  } catch (err) {
    console.error("EMAIL RECEIPT ERROR:", err);
    res.status(500).json({ message: err.message || "Failed to email receipt" });
  }
});

/* =========================
   PRINT / DOWNLOAD RECEIPT
========================= */
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
