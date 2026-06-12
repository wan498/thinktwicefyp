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

/* ===================== MYSQL (RAILWAY SAFE CONFIG) ===================== */

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
    console.log("✅ MySQL Connected");
    conn.release();
  } catch (err) {
    console.error("❌ MySQL Connection Error:", err.message);
  }
})();

/* ===================== PATH ===================== */

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

/* ===================== GROQ API ===================== */

const GROQ_API_KEY = process.env.GROQ_API_KEY;

/* ===================== AI ANALYZE ===================== */

app.post("/api/analyze", async (req, res) => {
  try {
    const { prompt, aiMode, roles = [], modes = [], singleMode = false } = req.body;

    const finalRoles = roles.length ? roles : ["Investor"];
    const finalModes = modes.length ? modes : ["Critic"];

    let combinations = [];

    if (singleMode) {
      combinations = [{ role: finalRoles[0], mode: finalModes[0] }];
    } else {
      for (const r of finalRoles) {
        for (const m of finalModes) {
          combinations.push({ role: r, mode: m });
        }
      }
    }

    let systemPrompt = "";

    if (aiMode === "chatgpt") {
      systemPrompt = `
You are a professional financial AI assistant.

Return structured output:
📊 Analysis
🧮 Calculations
📉 Interpretation
⚠️ Risk
✅ Recommendation
`;
    } else if (aiMode === "concept") {
      systemPrompt = `
STRICT ANALYST MODE

${combinations.map(c => `ROLE: ${c.role}\nMODE: ${c.mode}\n---`).join("\n")}

FORMAT:
ROLE: <ROLE>
MODE: <MODE>

📊 SCORE:
⚠️ RISK:
🎯 VERDICT:
🧠 CRITICISM:
💡 INSIGHT:
🔥 FINAL:
`;
    } else {
      systemPrompt = "You are a helpful AI assistant.";
    }

    const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${GROQ_API_KEY}`,
      },
      body: JSON.stringify({
        model: "llama-3.1-8b-instant",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: prompt }
        ],
        temperature: aiMode === "concept" ? 0.6 : 0.3,
        max_tokens: 2500
      }),
    });

    const data = await response.json();
    const result = data?.choices?.[0]?.message?.content;

    if (!result) {
      return res.status(500).json({ error: "No AI response", raw: data });
    }

    res.json({ result });

  } catch (err) {
    console.error("AI ERROR:", err);
    res.status(500).json({ error: err.message });
  }
});

/* ===================== SIGNUP ===================== */

app.post("/signup", async (req, res) => {
  try {
    const { fullname, email, password } = req.body;

    const [check] = await db.query(
      "SELECT * FROM users WHERE email=?",
      [email]
    );

    if (check.length > 0) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await db.query(
      "INSERT INTO users(fullname, email, password) VALUES (?, ?, ?)",
      [fullname, email, hashedPassword]
    );

    res.json({ message: "Account created successfully" });

  } catch (err) {
    console.error("SIGNUP ERROR:", err);
    res.status(500).json({ message: err.message });
  }
});

/* ===================== LOGIN ===================== */

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const [rows] = await db.query(
    "SELECT * FROM users WHERE email=?",
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

/* ===================== RESET PASSWORD ===================== */

app.post("/check-email", async (req, res) => {
  const { email } = req.body;

  const [rows] = await db.query(
    "SELECT * FROM users WHERE email=?",
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

  res.json({
    success: true,
    message: "Password updated successfully",
  });
});

/* ===================== START SERVER ===================== */

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
