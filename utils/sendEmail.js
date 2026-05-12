import nodemailer from "nodemailer";

const sendEmail = async ({ to, subject, html, attachmentPath }) => {
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,           // 🔴 REQUIRED
    port: Number(process.env.EMAIL_PORT),   // 🔴 REQUIRED
    secure: false,                           // Gmail uses STARTTLS
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_APP_PASSWORD
    }
  });

  const mailOptions = {
    from: `"${process.env.EMAIL_FROM_NAME}" <${process.env.EMAIL_FROM_ADDRESS}>`,
    to,
    subject,
    html,
    attachments: attachmentPath
      ? [{ path: attachmentPath }]
      : []
  };

  await transporter.sendMail(mailOptions);
};

export default sendEmail;