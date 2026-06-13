const express = require("express");
const { Pool } = require("pg");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.get("/", (req, res) => {
  res.json({ status: "Speak server is running" });
});

app.post("/api/register", async (req, res) => {
  const { userId, publicKey, signaturePublicKey, signaturePrivateKey } = req.body;
  if (!userId || !publicKey || !signaturePublicKey || !signaturePrivateKey) {
    return res.status(400).json({ error: "Missing fields" });
  }
  
  try {
    await pool.query(
      `INSERT INTO users(id, public_key, signature_public_key, signature_private_key, created_at)
       VALUES($1, $2, $3, $4, $5)
       ON CONFLICT(id) DO UPDATE SET public_key = $2, signature_public_key = $3, signature_private_key = $4`,
      [userId, publicKey, signaturePublicKey, signaturePrivateKey, Date.now()]
    );
    
    const token = crypto.createHmac("sha256", process.env.SESSION_SECRET || "speak_secret").update(userId).digest("hex");
    res.json({ token, userId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

app.get("/api/public_key/:userId", async (req, res) => {
  const { userId } = req.params;
  const result = await pool.query(
    "SELECT public_key, signature_public_key FROM users WHERE id = $1",
    [userId]
  );
  if (result.rows.length === 0) {
    return res.status(404).json({ error: "User not found" });
  }
  res.json(result.rows[0]);
});

app.post("/api/send_message", async (req, res) => {
  const { senderId, recipientId, encryptedPayload, nonce } = req.body;
  await pool.query(
    "INSERT INTO messages(sender_id, recipient_id, encrypted_payload, nonce, timestamp) VALUES($1, $2, $3, $4, $5)",
    [senderId, recipientId, encryptedPayload, nonce, Date.now()]
  );
  res.json({ success: true });
});

app.get("/api/messages/:userId", async (req, res) => {
  const { userId } = req.params;
  const result = await pool.query(
    "SELECT sender_id, encrypted_payload, nonce, timestamp FROM messages WHERE recipient_id = $1 ORDER BY timestamp ASC",
    [userId]
  );
  res.json(result.rows);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Speak server running on port ${PORT}`));
