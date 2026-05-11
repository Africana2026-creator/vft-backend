import express from "express";
import Enquiry from "../models/Enquiry.js";

const router = express.Router();

/* =========================
   CREATE ENQUIRY
========================= */
router.post("/", async (req, res) => {
  try {
    const enquiry = new Enquiry(req.body);
    await enquiry.save();
    res.status(201).json(enquiry);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to save enquiry" });
  }
});

/* =========================
   GET ALL ENQUIRIES (ADMIN)
========================= */
router.get("/", async (req, res) => {
  try {
    const enquiries = await Enquiry.find().sort({ createdAt: -1 });
    res.json(enquiries);
  } catch (error) {
    console.error("FETCH ERROR:", error);
    res.status(500).json({ message: "Failed to fetch enquiries" });
  }
});

export default router;