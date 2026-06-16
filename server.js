import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mysql from "mysql2/promise";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const app = express();

/* ===================== FIXED CORS ===================== */
app.use(cors({
  origin: "*"
}));

app.use(express.json());

/* ===================== MYSQL (RAILWAY SAFE) ===================== */

const db = mysql.createPool({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT,
  waitForConnections: true,
  connectionLimit: 10
});

/* test DB */
db.query("SELECT 1")
  .then(() => console.log("✅ MySQL Connected"))
  .catch(err => console.log("❌ MySQL Error:", err));

/* ===================== PATH ===================== */

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

/* ===================== SIGNUP ===================== */

app.post("/signup", async (req, res) => {
  try {
    const { fullname, email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    await db.query(
      "INSERT INTO users(fullname, email, password) VALUES (?, ?, ?)",
      [fullname, email, hashedPassword]
    );

    res.json({ message: "Account created successfully" });
  } catch (err) {
    res.status(400).json({ message: "Email already exists" });
  }
});

/* ===================== LOGIN ===================== */

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const [rows] = await db.query(
    "SELECT * FROM users WHERE email = ?",
    [email]
  );

  if (rows.length === 0) {
    return res.json({ message: "User not found" });
  }

  const user = rows[0];

  const valid = await bcrypt.compare(password, user.password);

  if (!valid) {
    return res.json({ message: "Wrong password" });
  }

  res.json({
    message: "Login successful",
    user: {
      id: user.id,
      fullname: user.fullname,
      email: user.email,
    },
  });
});

/* ===================== CHECK EMAIL ===================== */

app.post("/check-email", async (req, res) => {
  const { email } = req.body;

  const [rows] = await db.query(
    "SELECT * FROM users WHERE email = ?",
    [email]
  );

  if (rows.length === 0) {
    return res.json({ exists: false });
  }

  const token = crypto.randomBytes(32).toString("hex");
  const expiry = new Date(Date.now() + 15 * 60 * 1000);

  await db.query(
    "UPDATE users SET reset_token=?, reset_expiry=? WHERE email=?",
    [token, expiry, email]
  );

  res.json({ exists: true, token });
});

/* ===================== RESET PASSWORD ===================== */

app.post("/reset-password", async (req, res) => {
  const { email, token, newPassword } = req.body;

  const [rows] = await db.query(
    "SELECT * FROM users WHERE email=? AND reset_token=?",
    [email, token]
  );

  if (rows.length === 0) {
    return res.json({ success: false, message: "Invalid token" });
  }

  const user = rows[0];

  if (new Date(user.reset_expiry) < new Date()) {
    return res.json({ success: false, message: "Token expired" });
  }

  const hashed = await bcrypt.hash(newPassword, 10);

  await db.query(
    `UPDATE users 
     SET password=?, reset_token=NULL, reset_expiry=NULL 
     WHERE email=?`,
    [hashed, email]
  );

  res.json({ success: true, message: "Password updated successfully" });
});

/* ===================== RAILWAY FIX ===================== */

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Server running on port ${PORT}`);
});
