import mongoose from "mongoose";

const enquirySchema = new mongoose.Schema({
  full_name: String,
  email: String,
  phone: String,
  country: String,
  room_type: String,
  rooms: Number,
  check_in: String,
  check_out: String,
  adults: Number,
  children: Number,
  board_preference: String,
  airport_transfer: String,
  contact_method: String,
  arrival_time: String,
  special_requests: String,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

export default mongoose.model("Enquiry", enquirySchema);