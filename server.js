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

app.use(cors());
app.use(express.json());

/* ===================== MYSQL CONNECTION (RAILWAY SAFE) ===================== */

const db = mysql.createPool({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: Number(process.env.MYSQLPORT),
  waitForConnections: true,
  connectionLimit: 10,
});

/* TEST CONNECTION */
(async () => {
  try {
    const conn = await db.getConnection();
    console.log("✅ MySQL Connected Successfully");
    conn.release();
  } catch (err) {
    console.error("❌ MySQL Connection Error:", err.message);
  }
})();

/* ===================== PATH ===================== */

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.static(path.join(__dirname, "public")));

/* ===================== HOME ===================== */

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

/* ===================== SIGNUP ===================== */

app.post("/signup", async (req, res) => {
  try {
    console.log("🔥 SIGNUP REQUEST:", req.body);

    const { fullname, email, password } = req.body;

    if (!fullname || !email || !password) {
      return res.status(400).json({ message: "Missing fields" });
    }

    const [existing] = await db.query(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    if (existing.length > 0) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await db.query(
      "INSERT INTO users (fullname, email, password) VALUES (?, ?, ?)",
      [fullname, email, hashedPassword]
    );

    console.log("✅ INSERT RESULT:", result);

    res.json({ message: "Account created successfully" });

  } catch (err) {
    console.error("❌ SIGNUP ERROR:", err);
    res.status(500).json({ message: err.message });
  }
});

/* ===================== LOGIN ===================== */

app.post("/login", async (req, res) => {
  try {
    console.log("🔥 LOGIN REQUEST:", req.body);

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

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: err.message });
  }
});

/* ===================== CHECK EMAIL ===================== */

app.post("/check-email", async (req, res) => {
  try {
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

  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ===================== RESET PASSWORD ===================== */

app.post("/reset-password", async (req, res) => {
  try {
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

    res.json({
      success: true,
      message: "Password updated successfully",
    });

  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ===================== START SERVER ===================== */

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
