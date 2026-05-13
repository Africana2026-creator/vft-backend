import express from "express";
import fs from "fs";
import Booking from "../models/Booking.js";
import { generateBookingRef } from "../utils/generateBookingRef.js";
import authMiddleware from "../middleware/authMiddleware.js";
import generateReceipt from "../utils/generateReceipt.js";
import sendReceiptEmail from "../utils/sendReceiptEmail.js";

const router = express.Router();

/**
 * ===============================
 * CUSTOMER: CREATE BOOKING
 * Public route
 * ===============================
 */
router.post("/", async (req, res) => {
  try {
    console.log("📩 Incoming booking:", req.body);

    const {
      name,
      email,
      phone,
      guests,
      arrivalDate,
      arrivalTime,
      pickupLocation,
      flightNumber,
      country,
      paymentMethod,
      specialRequests,
      services,
      totalPrice
    } = req.body;

    if (!services || services.length === 0) {
      return res.status(400).json({
        success: false,
        message: "No services selected"
      });
    }

    const bookingRef = generateBookingRef();

    const booking = new Booking({
      bookingRef,
      name,
      email,
      phone,
      guests,
      arrivalDate,
      arrivalTime,
      pickupLocation,
      flightNumber,
      country,
      paymentMethod,
      specialRequests,
      services,
      totalPrice
    });

    await booking.save();

    // 📄 Generate receipt PDF
    const pdfPath = await generateReceipt(booking);
    const pdfBuffer = fs.readFileSync(pdfPath);

    // 📧 Send receipt email
    await sendReceiptEmail(
      booking.email.trim(),
      pdfBuffer,
      booking.bookingRef
    );

    res.status(201).json({
      success: true,
      message: "Booking confirmed & receipt emailed",
      bookingRef
    });

  } catch (error) {
    console.error("❌ Booking error:", error);
    res.status(500).json({
      success: false,
      message: "Booking failed"
    });
  }
});

/**
 * ===============================
 * ADMIN: GET ALL BOOKINGS
 * Protected route (JWT)
 * ===============================
 */
router.get("/", authMiddleware, async (req, res) => {
  try {
    const bookings = await Booking.find().sort({ createdAt: -1 });
    res.json(bookings);
  } catch (error) {
    console.error("❌ Fetch bookings error:", error);
    res.status(500).json({
      message: "Failed to fetch bookings"
    });
  }
});

export default router;