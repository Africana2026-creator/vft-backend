import "dotenv/config";
import dns from "node:dns/promises";
import nodemailer from "nodemailer";

let transporterPromise;

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

async function resolveSmtpHost() {
  const smtpHost = process.env.SMTP_HOST?.trim() || "smtp.gmail.com";

  try {
    const { address } = await dns.lookup(smtpHost, { family: 4 });
    return {
      smtpHost,
      smtpAddress: address
    };
  } catch (lookupError) {
    try {
      const addresses = await dns.resolve4(smtpHost);
      if (addresses.length) {
        return {
          smtpHost,
          smtpAddress: addresses[0]
        };
      }
    } catch {
      // Fall through to the final error below.
    }

    throw new Error(`Could not resolve an IPv4 SMTP address for ${smtpHost}: ${lookupError.message}`);
  }
}

async function createTransporter() {
  const { gmailUser, gmailPass } = getEmailConfig();
  const { smtpHost, smtpAddress } = await resolveSmtpHost();
  const smtpPort = Number(process.env.SMTP_PORT || 465);

  return nodemailer.createTransport({
    host: smtpAddress,
    port: smtpPort,
    secure: smtpPort === 465,
    auth: {
      user: gmailUser,
      pass: gmailPass
    },
    tls: {
      servername: smtpHost
    }
  });
}

async function getTransporter() {
  if (!transporterPromise) {
    transporterPromise = createTransporter().catch((error) => {
      transporterPromise = null;
      throw error;
    });
  }

  return transporterPromise;
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
    const transporter = await getTransporter();

    return await transporter.sendMail({
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
