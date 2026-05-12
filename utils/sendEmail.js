import nodemailer from "nodemailer";
import fs from "fs";

const gmailUser = process.env.GMAIL_USER?.trim();
const gmailPassword = process.env.GMAIL_APP_PASSWORD?.trim();
const fromName =
  process.env.EMAIL_FROM_NAME?.trim() || "Victoria Falls Transporters";
const fromAddress =
  process.env.EMAIL_FROM_ADDRESS?.trim() || gmailUser || "no-reply@example.com";

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

export default async function sendEmail({ to, subject, html, attachmentPath }) {
  if (!gmailUser || !gmailPassword) {
    throw new Error("Missing Gmail SMTP credentials in environment variables");
  }

  const mailOptions = {
    from: `"${fromName}" <${fromAddress}>`,
    to: typeof to === "string" ? to.trim() : to,
    subject,
    html,
    attachments: attachmentPath && fs.existsSync(attachmentPath)
      ? [{ filename: "receipt.pdf", path: attachmentPath }]
      : []
  };

  await transporter.sendMail(mailOptions);
}
