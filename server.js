import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pg from "pg";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json());

/* ===================== DATABASE (NEON POSTGRES) ===================== */

const { Pool } = pg;

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

db.query("SELECT 1")
  .then(() => console.log("✅ PostgreSQL Connected (Neon)"))
  .catch(err => console.log("❌ DB Error:", err));

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
      "INSERT INTO users(fullname, email, password) VALUES ($1, $2, $3)",
      [fullname, email, hashedPassword]
    );

    res.json({ message: "Account created successfully" });

  } catch (err) {
    console.error(err);
    res.status(400).json({ message: "Email already exists" });
  }
});

/* ===================== LOGIN ===================== */

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await db.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    const rows = result.rows;

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
    res.status(500).json({ message: "Server error" });
  }
});

/* ===================== CHECK EMAIL ===================== */

app.post("/check-email", async (req, res) => {
  try {
    const { email } = req.body;

    const result = await db.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    const rows = result.rows;

    if (rows.length === 0) {
      return res.json({ exists: false });
    }

    const token = crypto.randomBytes(32).toString("hex");
    const expiry = new Date(Date.now() + 15 * 60 * 1000);

    await db.query(
      "UPDATE users SET reset_token=$1, reset_expiry=$2 WHERE email=$3",
      [token, expiry, email]
    );

    res.json({ exists: true, token });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

/* ===================== RESET PASSWORD ===================== */

app.post("/reset-password", async (req, res) => {
  try {
    const { email, token, newPassword } = req.body;

    const result = await db.query(
      "SELECT * FROM users WHERE email=$1 AND reset_token=$2",
      [email, token]
    );

    const rows = result.rows;

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
       SET password=$1, reset_token=NULL, reset_expiry=NULL 
       WHERE email=$2`,
      [hashed, email]
    );

    res.json({
      success: true,
      message: "Password updated successfully",
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

/* ===================== REPORT ===================== */

app.post("/report", async (req, res) => {
  try {
    const {
      userId,
      email,
      reason,
      description,
      conversation,
      reported_by
    } = req.body;

    const result = await db.query(
      `INSERT INTO reports 
      (user_id, email, reason, description, conversation, reported_by)
      VALUES ($1,$2,$3,$4,$5,$6)
      RETURNING id`,
      [
        userId || null,
        email || "",
        reason,
        description || "",
        conversation || "",
        reported_by || "user"
      ]
    );

    res.json({
      success: true,
      reportId: result.rows[0].id,
      message: "Report submitted successfully"
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ===================== ACTION LOG ===================== */

app.post("/action", async (req, res) => {
  try {
    const { email, action_type, pdf_name, conversation } = req.body;

    await db.query(
      `INSERT INTO user_actions 
      (email, action_type, pdf_name, conversation, created_at)
      VALUES ($1,$2,$3,$4,NOW())`,
      [email, action_type, pdf_name, conversation]
    );

    res.json({ success: true });

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});

/* ===================== START SERVER ===================== */

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
