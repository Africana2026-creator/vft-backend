import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: process.env.EMAIL_PORT == 465, // true for 465, false for others
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

const sendEmail = async ({ to, subject, html, attachments = [] }) => {
  return transporter.sendMail({
    from: `"Victoria Falls Transporters" <${process.env.EMAIL_USER}>`,
    to,
    subject,
    html,
    attachments
  });
};

export default sendEmail;