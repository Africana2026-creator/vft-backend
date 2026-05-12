import nodemailer from "nodemailer";
import "dotenv/config";

const gmailUser = process.env.GMAIL_USER?.trim();
const gmailPassword = process.env.GMAIL_APP_PASSWORD?.trim();

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: gmailUser,
    pass: gmailPassword
  },
  tls: {
    rejectUnauthorized: false
  }
});

export default async function sendReceiptEmail(to, pdfBuffer, bookingRef) {
  if (!gmailUser || !gmailPassword) {
    throw new Error("Missing Gmail SMTP credentials in environment variables");
  }

  await transporter.sendMail({
    from: `"Victoria Falls Transporters" <${gmailUser}>`,
    to: typeof to === "string" ? to.trim() : to,
    subject: `Your Booking Receipt (${bookingRef})`,
    text: "Please find your booking receipt attached.",
    attachments: [
      {
        filename: `receipt-${bookingRef}.pdf`,
        content: pdfBuffer
      }
    ]
  });
}
