import generateReceiptStream from "./generateReceiptStream.js";

export default function generateReceiptBuffer(booking) {
  return new Promise((resolve, reject) => {
    const doc = generateReceiptStream(booking);
    const chunks = [];

    doc.on("data", (chunk) => chunks.push(chunk));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    doc.end();
  });
}
