import PDFDocument from "pdfkit";
import buildReceiptPdf from "./buildReceiptPdf.js";

export default function generateReceiptStream(booking) {
  const doc = new PDFDocument({ margin: 50 });
  buildReceiptPdf(doc, booking);

  return doc;
}
