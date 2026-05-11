import express from "express";
import Enquiry from "../models/Enquiry.js";
import sendEmail from "../utils/sendEmail.js";

const router = express.Router();

/* =========================
   CREATE ENQUIRY + EMAIL ADMIN
========================= */
router.post("/", async (req, res) => {
  try {
    const enquiry = await Enquiry.create(req.body);

    // 📧 EMAIL ADMIN
    await sendEmail({
      to: process.env.ADMIN_EMAIL,
      subject: "📩 New Accommodation Enquiry",
      html: `
        <h2>New Accommodation Enquiry</h2>
        <p><strong>Name:</strong> ${enquiry.full_name}</p>
        <p><strong>Email:</strong> ${enquiry.email}</p>
        <p><strong>Phone:</strong> ${enquiry.phone}</p>
        <p><strong>Country:</strong> ${enquiry.country}</p>
        <p><strong>Room Type:</strong> ${enquiry.room_type}</p>
        <p><strong>Rooms:</strong> ${enquiry.rooms}</p>
        <p><strong>Check-in:</strong> ${enquiry.check_in}</p>
        <p><strong>Check-out:</strong> ${enquiry.check_out}</p>
        <p><strong>Adults:</strong> ${enquiry.adults}</p>
        <p><strong>Children:</strong> ${enquiry.children}</p>
        <p><strong>Board:</strong> ${enquiry.board_preference}</p>
        <p><strong>Airport Transfer:</strong> ${enquiry.airport_transfer}</p>
        <p><strong>Contact Method:</strong> ${enquiry.contact_method}</p>
        <p><strong>Arrival Time:</strong> ${enquiry.arrival_time || "N/A"}</p>
        <p><strong>Special Requests:</strong><br>${enquiry.special_requests || "None"}</p>
        <hr />
        <p>Login to admin dashboard to manage this enquiry.</p>
      `
    });

    res.status(201).json({
      success: true,
      message: "Enquiry submitted successfully"
    });

  } catch (error) {
    console.error("ENQUIRY ERROR:", error);
    res.status(500).json({
      success: false,
      message: "Failed to submit enquiry"
    });
  }
});

export default router;