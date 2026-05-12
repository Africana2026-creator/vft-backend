import express from "express";
import Enquiry from "../models/Enquiry.js";
import protectAdmin from "../middleware/authMiddleware.js";

const router = express.Router();
const allowedStatuses = new Set(["new", "contacted", "confirmed", "cancelled"]);

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
router.get("/", protectAdmin, async (req, res) => {
  try {
    const enquiries = await Enquiry.find().sort({ createdAt: -1 });
    res.json(enquiries);
  } catch (error) {
    console.error("FETCH ERROR:", error);
    res.status(500).json({ message: "Failed to fetch enquiries" });
  }
});

/* =========================
   UPDATE ENQUIRY STATUS (ADMIN)
========================= */
router.patch("/:id", protectAdmin, async (req, res) => {
  try {
    const { status } = req.body;

    if (!allowedStatuses.has(status)) {
      return res.status(400).json({ message: "Invalid enquiry status" });
    }

    const enquiry = await Enquiry.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true, runValidators: true }
    );

    if (!enquiry) {
      return res.status(404).json({ message: "Enquiry not found" });
    }

    res.json({
      message: "Enquiry status updated successfully",
      enquiry
    });
  } catch (error) {
    console.error("STATUS UPDATE ERROR:", error);
    res.status(500).json({ message: "Failed to update enquiry status" });
  }
});

/* =========================
   DELETE ENQUIRY (ADMIN)
========================= */
router.delete("/:id", protectAdmin, async (req, res) => {
  try {
    const enquiry = await Enquiry.findByIdAndDelete(req.params.id);

    if (!enquiry) {
      return res.status(404).json({ message: "Enquiry not found" });
    }

    res.json({ message: "Enquiry deleted successfully" });
  } catch (error) {
    console.error("DELETE ENQUIRY ERROR:", error);
    res.status(500).json({ message: "Failed to delete enquiry" });
  }
});

export default router;
