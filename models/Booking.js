import mongoose from "mongoose";

const bookingSchema = new mongoose.Schema(
  {
    bookingRef: {
      type: String,
      unique: true,
      index: true,
    },

    name: String,
    email: String,
    phone: String,
    guests: Number,
    arrivalDate: String,
    arrivalTime: String,
    pickupLocation: String,
    flightNumber: String,
    country: String,
    paymentMethod: String,
    specialRequests: String,

    services: [
      {
        name: String,
        unitPrice: Number,
        passengers: Number,
        price: Number,
      },
    ],

    totalPrice: Number,
  },
  { timestamps: true }
);

/**
 * ✅ MONGOOSE v7+ SAFE PRE-SAVE HOOK
 * NO next()
 */
bookingSchema.pre("save", function () {
  if (!this.bookingRef) {
    this.bookingRef = `VFT-${Date.now()}-${Math.floor(
      1000 + Math.random() * 9000
    )}`;
  }
});

export default mongoose.model("Booking", bookingSchema);