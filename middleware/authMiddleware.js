import jwt from "jsonwebtoken";

export default function adminAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "No token provided" });
    }

    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // 🔑 IMPORTANT: normalize admin object
    req.admin = {
      id: decoded.id,
      email: decoded.email
    };

    next();
  } catch (err) {
    console.error("JWT ERROR:", err.message);
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}