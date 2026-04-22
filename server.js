import express from "express";
import helmet from "helmet";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";

import bookingRoutes from "./routes/bookingRoutes.js";
import adminRoutes from "./routes/adminRoutes.js";

dotenv.config();

/* =======================
   APP INIT (MUST BE FIRST)
======================= */
const app = express();

/* =======================
   CORS
======================= */
const allowedOrigins = [
  "https://victoriafalls-transporters.netlify.app",
  "https://vft-admin.netlify.app",
  "http://localhost:3000",
  "http://127.0.0.1:5502",
  "http://localhost:5502"
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Blocked by CORS: " + origin));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
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