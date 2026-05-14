import "dotenv/config";
import nodemailer from "nodemailer";

let transporter;

function getEmailConfig() {
  const gmailUser = process.env.GMAIL_USER?.trim();
  const gmailPass = process.env.GMAIL_APP_PASSWORD?.trim();

  if (!gmailUser || !gmailPass) {
    throw new Error("Email service is not configured. Set GMAIL_USER and GMAIL_APP_PASSWORD.");
  }

  return {
    gmailUser,
    gmailPass,
    fromName: process.env.EMAIL_FROM_NAME?.trim() || "Victoria Falls Transporters",
    fromAddress: process.env.EMAIL_FROM_ADDRESS?.trim() || gmailUser
  };
}

function getTransporter() {
  if (!transporter) {
    const { gmailUser, gmailPass } = getEmailConfig();
    transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: gmailUser,
        pass: gmailPass
      }
    });
  }

  return transporter;
}

export default async function sendReceiptEmail(to, pdfBuffer, bookingRef) {
  if (!to?.trim()) {
    throw new Error("Customer email address is missing.");
  }

  if (!Buffer.isBuffer(pdfBuffer) || !pdfBuffer.length) {
    throw new Error("Receipt PDF could not be generated.");
  }

  const { fromName, fromAddress } = getEmailConfig();

  try {
    return await getTransporter().sendMail({
      from: `"${fromName}" <${fromAddress}>`,
      to: to.trim(),
      subject: `Your Booking Receipt (${bookingRef})`,
      text: "Please find your booking receipt attached.",
      attachments: [
        {
          filename: `receipt-${bookingRef}.pdf`,
          content: pdfBuffer
        }
      ]
    });
  } catch (error) {
    throw new Error(`Receipt email send failed: ${error.message}`);
  }
}
