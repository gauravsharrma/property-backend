// routes/auth.js
import express from "express";
import bcrypt from "bcrypt";
import pool from "../db.js";

const router = express.Router();

router.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id",
      [name, email, hashed]
    );
    res.json({ success: true, userId: result.rows[0].id });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: "Invalid email" });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: "Incorrect password" });

    res.json({ success: true, userId: user.id, name: user.name });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

export default router;
