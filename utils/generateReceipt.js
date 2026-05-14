import PDFDocument from "pdfkit";
import fs from "fs";
import path from "path";
import buildReceiptPdf from "./buildReceiptPdf.js";

export default function generateReceipt(booking) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50 });

    const filePath = path.join(
      process.cwd(),
      "receipts",
      `receipt-${booking.bookingRef}.pdf`
    );

    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const stream = fs.createWriteStream(filePath);
    doc.pipe(stream);

    buildReceiptPdf(doc, booking);

    doc.end();

    stream.on("finish", () => resolve(filePath));
    stream.on("error", reject);
  });
}
