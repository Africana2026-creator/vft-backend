import express from "express";
import Enquiry from "../models/Enquiry.js";
import sendEmail from "../utils/sendEmail.js";
import protectAdmin from "../middleware/authMiddleware.js";

const router = express.Router();

/* =========================
   CREATE ENQUIRY (PUBLIC)
========================= */
router.post("/", async (req, res) => {
  try {
    const enquiry = await Enquiry.create(req.body);

    await sendEmail({
      to: process.env.ADMIN_EMAIL,
      subject: "📩 New Accommodation Enquiry",
      html: `<h2>New Enquiry from ${enquiry.full_name}</h2>`
    });

    res.status(201).json({ success: true });

  } catch (error) {
    res.status(500).json({ success: false });
  }
});

/* =========================
   GET ALL ENQUIRIES (ADMIN)
========================= */
router.get("/", protectAdmin, async (req, res) => {
  const enquiries = await Enquiry.find().sort({ createdAt: -1 });
  res.json(enquiries);
});

/* =========================
   UPDATE STATUS (ADMIN)
========================= */
router.patch("/:id", protectAdmin, async (req, res) => {
  const updated = await Enquiry.findByIdAndUpdate(
    req.params.id,
    { status: req.body.status },
    { new: true }
  );
  res.json(updated);
});

/* =========================
   DELETE (ADMIN)
========================= */
router.delete("/:id", protectAdmin, async (req, res) => {
  await Enquiry.findByIdAndDelete(req.params.id);
  res.json({ success: true });
});

export default router;