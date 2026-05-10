import Enquiry from "../models/Enquiry.js";

/* =========================
   CREATE ENQUIRY (PUBLIC)
========================= */
export const createEnquiry = async (req, res) => {
  try {
    const enquiry = await Enquiry.create(req.body);

    res.status(201).json({
      success: true,
      message: "Enquiry submitted successfully",
      enquiry
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to submit enquiry",
      error: error.message
    });
  }
};

/* =========================
   GET ALL ENQUIRIES (ADMIN)
========================= */
export const getAllEnquiries = async (req, res) => {
  try {
    const enquiries = await Enquiry.find().sort({ createdAt: -1 });
    res.json(enquiries);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};