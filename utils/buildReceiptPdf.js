import fs from "fs";
import path from "path";

function formatMoney(value) {
  const amount = Number(value);
  return Number.isFinite(amount) ? amount.toFixed(2) : "0.00";
}

function getServices(booking) {
  return Array.isArray(booking?.services) ? booking.services : [];
}

export default function buildReceiptPdf(doc, booking) {
  const bookingDate = booking?.createdAt
    ? new Date(booking.createdAt).toDateString()
    : new Date().toDateString();
  const services = getServices(booking);
  const logoPath = path.join(process.cwd(), "public", "logo.png");

  if (fs.existsSync(logoPath)) {
    doc.image(logoPath, 50, 45, { width: 80 });
  }

  doc.fontSize(20).text("Victoria Falls Transporters", 150, 50);
  doc.fontSize(10).text("Africana Tours", 150, 75);
  doc.moveDown(3);

  doc.fontSize(14).text("Booking Receipt", { underline: true });
  doc.moveDown();
  doc.fontSize(11).text(`Name: ${booking?.name || "Customer"}`);
  doc.text(`Email: ${booking?.email || "Not provided"}`);
  doc.text(`Booking Ref: ${booking?.bookingRef || "Pending"}`);
  doc.text(`Date: ${bookingDate}`);
  doc.moveDown();

  doc.fontSize(13).text("Booked Services", { underline: true });
  doc.moveDown(0.5);

  if (services.length) {
    services.forEach((service, index) => {
      const name = service?.name || `Service ${index + 1}`;
      doc.text(`${name} - $${formatMoney(service?.price)}`);
    });
  } else {
    doc.text("No services recorded.");
  }

  doc.moveDown();
  doc.fontSize(14).text(`Total: $${formatMoney(booking?.totalPrice)}`, {
    align: "right"
  });

  doc.moveDown(3);
  doc.fontSize(10).text(
    "Thank you for booking with Victoria Falls Transporters - Africana Tours",
    { align: "center" }
  );
}
