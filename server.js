// ============ НАСТРОЙКИ СЕТИ ============
const dns = require('dns');
dns.setDefaultResultOrder('ipv4first');
process.env.NODE_OPTIONS = '--dns-result-order=ipv4first';

const express = require("express");
const { Pool } = require("pg");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" }));

// ============ ПОДКЛЮЧЕНИЕ К БАЗЕ ДАННЫХ ============
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 30000,
});

// ============ ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ============

async function hashPassword(password, salt = null) {
  if (!salt) salt = crypto.randomBytes(16).toString('hex');
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, 100000, 64, 'sha512', (err, derivedKey) => {
      if (err) reject(err);
      resolve({ hash: derivedKey.toString('hex'), salt });
    });
  });
}

async function verifyPassword(password, hash, salt) {
  const { hash: testHash } = await hashPassword(password, salt);
  return testHash === hash;
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ============ API ЭНДПОИНТЫ (ВСЕ ОТКРЫТЫЕ) ============

app.get("/", (req, res) => {
  res.json({ status: "Speak server is running", version: "2.0" });
});

// РЕГИСТРАЦИЯ
app.post("/api/register", async (req, res) => {
  try {
    const { username, password, displayName, publicKey, signaturePublicKey, signaturePrivateKey } = req.body;
    if (!username || !password || !displayName) return res.status(400).json({ error: "All fields required" });
    if (username.length < 3) return res.status(400).json({ error: "Username too short" });
    if (password.length < 6) return res.status(400).json({ error: "Password too short" });
    
    const existing = await pool.query('SELECT id FROM users_auth WHERE username = $1', [username]);
    if (existing.rows.length > 0) return res.status(409).json({ error: "Username already exists" });
    
    const { hash, salt } = await hashPassword(password);
    const userId = crypto.randomBytes(16).toString('hex');
    
    await pool.query(
      `INSERT INTO users_auth(id, username, password_hash, display_name, public_key, signature_public_key, signature_private_key, created_at)
       VALUES($1, $2, $3, $4, $5, $6, $7, $8)`,
      [userId, username, `${hash}.${salt}`, displayName, publicKey, signaturePublicKey, signaturePrivateKey, Date.now()]
    );
    
    const token = generateToken();
    
    res.json({ success: true, token, userId, username, displayName });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ЛОГИН
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Username and password required" });
    
    const result = await pool.query(
      'SELECT id, username, password_hash, display_name, public_key, signature_public_key, signature_private_key FROM users_auth WHERE username = $1',
      [username]
    );
    if (result.rows.length === 0) return res.status(401).json({ error: "Invalid credentials" });
    
    const user = result.rows[0];
    const [hash, salt] = user.password_hash.split('.');
    const isValid = await verifyPassword(password, hash, salt);
    if (!isValid) return res.status(401).json({ error: "Invalid credentials" });
    
    const token = generateToken();
    
    res.json({ 
      success: true, 
      token, 
      userId: user.id, 
      username: user.username, 
      display_name: user.display_name,
      public_key: user.public_key,
      signature_public_key: user.signature_public_key,
      signature_private_key: user.signature_private_key
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ПУБЛИЧНЫЙ КЛЮЧ
app.get("/api/public_key/:username", async (req, res) => {
  try {
    const { username } = req.params;
    const result = await pool.query("SELECT public_key FROM users_auth WHERE username = $1", [username]);
    if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });
    res.json({ public_key: result.rows[0].public_key });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ИНФОРМАЦИЯ О ПОЛЬЗОВАТЕЛЕ
app.get("/api/user_info/:username", async (req, res) => {
  try {
    const { username } = req.params;
    const result = await pool.query("SELECT id, username, display_name, public_key FROM users_auth WHERE username = $1", [username]);
    if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ПОИСК ПОЛЬЗОВАТЕЛЕЙ
app.get("/api/users/search", async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || q.length < 2) return res.json([]);
    const result = await pool.query(
      `SELECT id, username, display_name, public_key FROM users_auth WHERE display_name ILIKE $1 LIMIT 10`,
      [`%${q}%`]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Search error:', err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============ СООБЩЕНИЯ (ОТКРЫТЫЕ) ============

app.get("/api/messages", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT m.*, u.username as sender_username, u.display_name as sender_display_name
       FROM messages m
       JOIN users_auth u ON m.sender_id = u.id
       ORDER BY m.timestamp ASC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Get messages error:', err);
    res.json([]);
  }
});

app.post("/api/send_message", async (req, res) => {
  try {
    const { recipientUsername, encryptedPayload, nonce, senderUsername } = req.body;
    console.log("Send message to:", recipientUsername);
    
    let senderId = null;
    if (senderUsername) {
      const sender = await pool.query('SELECT id FROM users_auth WHERE username = $1', [senderUsername]);
      if (sender.rows.length > 0) senderId = sender.rows[0].id;
    }
    
    const recipient = await pool.query('SELECT id FROM users_auth WHERE username = $1', [recipientUsername]);
    if (recipient.rows.length === 0) {
      return res.status(404).json({ error: "Recipient not found" });
    }
    
    if (!senderId) senderId = recipient.rows[0].id;
    
    await pool.query(
      `INSERT INTO messages(sender_id, recipient_id, encrypted_payload, nonce, timestamp)
       VALUES($1, $2, $3, $4, $5)`,
      [senderId, recipient.rows[0].id, encryptedPayload, nonce || '', Date.now()]
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error('Send message error:', err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/verify", (req, res) => {
  res.json({ valid: true });
});

app.post("/api/logout", (req, res) => {
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;

async function startServer() {
  try {
    await pool.query('SELECT NOW()');
    console.log('✅ Database connected');
    app.listen(PORT, () => console.log(`✅ Speak server running on port ${PORT}`));
  } catch (err) {
    console.error('❌ Database connection error:', err.message);
  }
}

startServer();
