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

function generateSessionToken(userId) {
  const randomPart = crypto.randomBytes(32).toString('hex');
  const secret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
  const signature = crypto.createHmac('sha256', secret).update(userId + randomPart).digest('hex');
  return `${userId}.${randomPart}.${signature}`;
}

async function verifySessionToken(token) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [userId, randomPart, signature] = parts;
  const secret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
  const expectedSignature = crypto.createHmac('sha256', secret).update(userId + randomPart).digest('hex');
  if (signature !== expectedSignature) return null;
  try {
    const result = await pool.query('SELECT user_id, expires_at FROM sessions WHERE token = $1', [token]);
    if (result.rows.length === 0) return null;
    if (result.rows[0].expires_at < Date.now()) {
      await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
      return null;
    }
    return result.rows[0].user_id;
  } catch (err) {
    return null;
  }
}

async function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token provided' });
  const userId = await verifySessionToken(token);
  if (!userId) return res.status(401).json({ error: 'Invalid or expired token' });
  req.userId = userId;
  next();
}

// ============ API ЭНДПОИНТЫ ============

app.get("/", (req, res) => {
  res.json({ status: "Speak server is running", version: "2.0" });
});

// РЕГИСТРАЦИЯ
app.post("/api/register", async (req, res) => {
  try {
    const { username, password, displayName, publicKey, signaturePublicKey, signaturePrivateKey } = req.body;
    
    if (!username || !password || !displayName || !publicKey || !signaturePublicKey || !signaturePrivateKey) {
      return res.status(400).json({ error: "All fields required" });
    }
    
    const existing = await pool.query('SELECT id FROM users_auth WHERE username = $1', [username]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: "Username already exists" });
    }
    
    const { hash, salt } = await hashPassword(password);
    const userId = crypto.randomBytes(16).toString('hex');
    
    await pool.query(
      `INSERT INTO users_auth(id, username, password_hash, display_name, public_key, signature_public_key, signature_private_key, created_at)
       VALUES($1, $2, $3, $4, $5, $6, $7, $8)`,
      [userId, username, `${hash}.${salt}`, displayName, publicKey, signaturePublicKey, signaturePrivateKey, Date.now()]
    );
    
    const token = generateSessionToken(userId);
    const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
    await pool.query('INSERT INTO sessions(token, user_id, expires_at, created_at) VALUES($1, $2, $3, $4)', [token, userId, expiresAt, Date.now()]);
    
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
    
    const result = await pool.query(
      'SELECT id, username, password_hash, display_name, signature_private_key FROM users_auth WHERE username = $1',
      [username]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    
    const user = result.rows[0];
    const [hash, salt] = user.password_hash.split('.');
    const isValid = await verifyPassword(password, hash, salt);
    
    if (!isValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    
    const token = generateSessionToken(user.id);
    const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
    await pool.query('INSERT INTO sessions(token, user_id, expires_at, created_at) VALUES($1, $2, $3, $4)', [token, user.id, expiresAt, Date.now()]);
    
    res.json({ 
      success: true, 
      token, 
      userId: user.id, 
      username: user.username, 
      display_name: user.display_name,
      signature_private_key: user.signature_private_key
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ПОЛУЧИТЬ ПУБЛИЧНЫЙ КЛЮЧ
app.get("/api/public_key/:username", async (req, res) => {
  try {
    const { username } = req.params;
    const result = await pool.query("SELECT public_key FROM users_auth WHERE username = $1", [username]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json({ public_key: result.rows[0].public_key });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ОТПРАВИТЬ СООБЩЕНИЕ
app.post("/api/send_message", authMiddleware, async (req, res) => {
  try {
    const { recipientUsername, encryptedPayload, nonce } = req.body;
    
    const recipientResult = await pool.query('SELECT id FROM users_auth WHERE username = $1', [recipientUsername]);
    if (recipientResult.rows.length === 0) {
      return res.status(404).json({ error: "Recipient not found" });
    }
    
    await pool.query(
      `INSERT INTO messages(sender_id, recipient_id, encrypted_payload, nonce, timestamp)
       VALUES($1, $2, $3, $4, $5)`,
      [req.userId, recipientResult.rows[0].id, encryptedPayload, nonce, Date.now()]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Send message error:', err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ПОЛУЧИТЬ СООБЩЕНИЯ
app.get("/api/messages", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
         m.encrypted_payload, 
         m.nonce, 
         m.timestamp,
         u.username as sender_username,
         u.display_name as sender_display_name
       FROM messages m
       JOIN users_auth u ON m.sender_id = u.id
       WHERE m.recipient_id = $1
       ORDER BY m.timestamp ASC`,
      [req.userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Get messages error:', err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/verify", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, display_name FROM users_auth WHERE id = $1', [req.userId]);
    if (result.rows.length === 0) return res.status(401).json({ error: "User not found" });
    res.json({ valid: true, user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/logout", authMiddleware, async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Speak server running on port ${PORT}`));
