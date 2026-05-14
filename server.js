import "dotenv/config";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import mongoose from "mongoose";

import bookingRoutes from "./routes/bookingRoutes.js";
import adminRoutes from "./routes/adminRoutes.js";
import enquiryRoutes from "./routes/enquiryRoutes.js";

/* =======================
   APP INIT (MUST BE FIRST)
======================= */
const app = express();

/* =======================
   CORS
======================= */

const allowedOrigins = [
  "https://victoriafalls-transporters.netlify.app",
  "https://vftamdinusersonly.netlify.app",   // <-- your admin Netlify URL
  "http://127.0.0.1:5500",
  "http://localhost:5500",
  "http://127.0.0.1:5502",   // ✅ ADD THIS
  "http://localhost:5502"
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.options("*", cors());

/* =======================
   MIDDLEWARE
======================= */
app.use(express.json({ limit: "10kb" }));
app.use(helmet());


/* =======================
   DATABASE
======================= */
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ MongoDB connection failed:", err));

/* =======================
   ROUTES
======================= */
app.use("/api/bookings", bookingRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/enquiries", enquiryRoutes); // ✅

/* =======================
   TEST
======================= */
app.get("/", (req, res) => {
  res.send("Server is running");
});

/* =======================
   START SERVER
======================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
