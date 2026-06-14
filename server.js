// ============ НАСТРОЙКИ ============
const dns = require('dns');
dns.setDefaultResultOrder('ipv4first');
process.env.NODE_OPTIONS = '--dns-result-order=ipv4first';

const express = require("express");
const { Pool } = require("pg");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));

// ============ POSTGRESQL ============
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 30000,
});

// ============ ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ============
function isValidUsername(username) {
  return username && /^[a-zA-Z0-9_]{3,32}$/.test(username);
}

function isValidDisplayName(displayName) {
  return displayName && displayName.length >= 2 && displayName.length <= 50;
}

function isValidPassword(password) {
  return password && password.length >= 8 && password.length <= 128;
}

function isValidPublicKey(key) {
  return key && typeof key === 'string' && key.length <= 500;
}

function isValidNonce(nonce) {
  return nonce && typeof nonce === 'string' && nonce.length <= 100;
}

function isValidPayload(payload) {
  return payload && typeof payload === 'string' && payload.length <= 10000;
}

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

function generateSessionToken() {
  return crypto.randomBytes(64).toString('hex');
}

// ============ MIDDLEWARE ============
async function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ success: false, error: 'No token provided' });
  }
  try {
    const result = await pool.query(
      'SELECT user_id, expires_at FROM sessions WHERE token = $1',
      [token]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, error: 'Invalid token' });
    }
    if (result.rows[0].expires_at < Date.now()) {
      await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
      return res.status(401).json({ success: false, error: 'Token expired' });
    }
    req.userId = result.rows[0].user_id;
    next();
  } catch (err) {
    console.error('Auth error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
}

// ============ ИНИЦИАЛИЗАЦИЯ ТАБЛИЦ ============
async function initDatabase() {
  try {
    await pool.query('SELECT NOW()');
    console.log('✅ Database connected');
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users_auth (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        display_name TEXT NOT NULL,
        public_key TEXT NOT NULL,
        signature_public_key TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        last_login BIGINT
      )
    `);
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS sessions (
        id SERIAL PRIMARY KEY,
        user_id TEXT NOT NULL,
        token TEXT UNIQUE NOT NULL,
        created_at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL
      )
    `);
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        sender_id TEXT NOT NULL,
        recipient_id TEXT NOT NULL,
        encrypted_payload TEXT NOT NULL,
        nonce TEXT NOT NULL,
        timestamp BIGINT NOT NULL
      )
    `);
    
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_users_auth_username ON users_auth(username)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_users_auth_display_name ON users_auth(display_name)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)`);
    
    console.log('✅ Tables ready');
  } catch (err) {
    console.error('❌ Database init error:', err.message);
  }
}

// ============ HEALTH CHECK ============
app.get("/", async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: "ok", version: "3.0", database: "connected" });
  } catch (err) {
    res.json({ status: "ok", version: "3.0", database: "disconnected" });
  }
});

// ============ РЕГИСТРАЦИЯ ============
app.post("/api/register", async (req, res) => {
  try {
    const { username, password, displayName, publicKey, signaturePublicKey } = req.body;
    
    if (!username || !password || !displayName || !publicKey || !signaturePublicKey) {
      return res.status(400).json({ success: false, error: "All fields required" });
    }
    if (!isValidUsername(username)) {
      return res.status(400).json({ success: false, error: "Invalid username (3-32 chars, a-z, 0-9, _)" });
    }
    if (!isValidDisplayName(displayName)) {
      return res.status(400).json({ success: false, error: "Display name must be 2-50 characters" });
    }
    if (!isValidPassword(password)) {
      return res.status(400).json({ success: false, error: "Password must be 8-128 characters" });
    }
    if (!isValidPublicKey(publicKey) || !isValidPublicKey(signaturePublicKey)) {
      return res.status(400).json({ success: false, error: "Invalid public key" });
    }
    
    const existing = await pool.query('SELECT id FROM users_auth WHERE username = $1', [username]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ success: false, error: "Username already exists" });
    }
    
    const existingDisplay = await pool.query('SELECT id FROM users_auth WHERE display_name = $1', [displayName]);
    if (existingDisplay.rows.length > 0) {
      return res.status(409).json({ success: false, error: "Display name already taken" });
    }
    
    const { hash, salt } = await hashPassword(password);
    const userId = crypto.randomBytes(16).toString('hex');
    
    await pool.query(
      `INSERT INTO users_auth(id, username, password_hash, display_name, public_key, signature_public_key, created_at)
       VALUES($1, $2, $3, $4, $5, $6, $7)`,
      [userId, username, `${hash}.${salt}`, displayName, publicKey, signaturePublicKey, Date.now()]
    );
    
    const token = generateSessionToken();
    const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
    await pool.query(
      'INSERT INTO sessions(user_id, token, created_at, expires_at) VALUES($1, $2, $3, $4)',
      [userId, token, Date.now(), expiresAt]
    );
    
    console.log(`✅ User registered: ${username}`);
    res.json({ success: true, token, userId, username, displayName });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});

// ============ ЛОГИН ============
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, error: "Username and password required" });
    }
    
    const result = await pool.query(
      'SELECT id, username, password_hash, display_name, public_key, signature_public_key FROM users_auth WHERE username = $1',
      [username]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, error: "Invalid credentials" });
    }
    
    const user = result.rows[0];
    const [hash, salt] = user.password_hash.split('.');
    const isValid = await verifyPassword(password, hash, salt);
    if (!isValid) {
      return res.status(401).json({ success: false, error: "Invalid credentials" });
    }
    
    await pool.query('UPDATE users_auth SET last_login = $1 WHERE id = $2', [Date.now(), user.id]);
    await pool.query('DELETE FROM sessions WHERE user_id = $1 AND expires_at < $2', [user.id, Date.now()]);
    
    const token = generateSessionToken();
    const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
    await pool.query(
      'INSERT INTO sessions(user_id, token, created_at, expires_at) VALUES($1, $2, $3, $4)',
      [user.id, token, Date.now(), expiresAt]
    );
    
    console.log(`✅ User logged in: ${username}`);
    res.json({
      success: true,
      token,
      userId: user.id,
      username: user.username,
      display_name: user.display_name,
      public_key: user.public_key,
      signature_public_key: user.signature_public_key
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});

// ============ ВЫХОД ============
app.post("/api/logout", authMiddleware, async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
    console.log(`✅ User ${req.userId} logged out`);
    res.json({ success: true });
  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});

// ============ ПУБЛИЧНЫЙ КЛЮЧ ============
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

// ============ ИНФОРМАЦИЯ О ПОЛЬЗОВАТЕЛЕ ============
app.get("/api/user_info/:username", async (req, res) => {
  try {
    const { username } = req.params;
    const result = await pool.query(
      "SELECT id, username, display_name, public_key FROM users_auth WHERE username = $1",
      [username]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============ ПОИСК ПОЛЬЗОВАТЕЛЕЙ ============
app.get("/api/users/search", async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || q.length < 2) return res.json([]);
    const result = await pool.query(
      `SELECT id, username, display_name, public_key 
       FROM users_auth 
       WHERE display_name ILIKE $1 
       ORDER BY display_name ASC 
       LIMIT 20`,
      [`%${q}%`]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Search error:', err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============ ОТПРАВКА СООБЩЕНИЯ ============
app.post("/api/send_message", authMiddleware, async (req, res) => {
  try {
    const { recipientUsername, encryptedPayload, nonce } = req.body;
    
    if (!recipientUsername) {
      return res.status(400).json({ success: false, error: "Recipient required" });
    }
    if (!isValidPayload(encryptedPayload)) {
      return res.status(400).json({ success: false, error: "Message too large" });
    }
    if (!isValidNonce(nonce)) {
      return res.status(400).json({ success: false, error: "Invalid nonce" });
    }
    
    const recipient = await pool.query('SELECT id FROM users_auth WHERE username = $1', [recipientUsername]);
    if (recipient.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Recipient not found" });
    }
    
    await pool.query(
      `INSERT INTO messages(sender_id, recipient_id, encrypted_payload, nonce, timestamp)
       VALUES($1, $2, $3, $4, $5)`,
      [req.userId, recipient.rows[0].id, encryptedPayload, nonce, Date.now()]
    );
    
    console.log(`✅ Message sent from ${req.userId} to ${recipientUsername}`);
    res.json({ success: true });
  } catch (err) {
    console.error('Send error:', err);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});

// ============ ПОЛУЧЕНИЕ СООБЩЕНИЙ ============
app.get("/api/messages", authMiddleware, async (req, res) => {
  try {
    const { withUser, limit = 50, offset = 0 } = req.query;
    let query = `
      SELECT m.id, m.encrypted_payload, m.nonce, m.timestamp,
             u1.username as sender_username, u1.display_name as sender_display_name,
             u2.username as recipient_username, u2.display_name as recipient_display_name
      FROM messages m
      JOIN users_auth u1 ON m.sender_id = u1.id
      JOIN users_auth u2 ON m.recipient_id = u2.id
      WHERE m.sender_id = $1 OR m.recipient_id = $1
    `;
    const params = [req.userId];
    
    if (withUser) {
      const userResult = await pool.query('SELECT id FROM users_auth WHERE username = $1', [withUser]);
      if (userResult.rows.length === 0) {
        return res.status(404).json({ error: "User not found" });
      }
      const otherId = userResult.rows[0].id;
      query += ` AND (m.sender_id = $2 OR m.recipient_id = $2)`;
      params.push(otherId);
    }
    
    query += ` ORDER BY m.timestamp DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(parseInt(limit), parseInt(offset));
    
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error('Messages error:', err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============ ПРОВЕРКА ТОКЕНА ============
app.get("/api/verify", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, display_name FROM users_auth WHERE id = $1',
      [req.userId]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ valid: false });
    }
    res.json({ valid: true, user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ valid: false });
  }
});

// ============ GRACEFUL SHUTDOWN ============
process.on('SIGINT', async () => {
  console.log('🛑 Shutting down...');
  await pool.end();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('🛑 Shutting down...');
  await pool.end();
  process.exit(0);
});

// ============ ЗАПУСК СЕРВЕРА ============
const PORT = process.env.PORT || 3000;

async function startServer() {
  await initDatabase();
  app.listen(PORT, () => {
    console.log(`✅ Speak server running on port ${PORT}`);
    console.log(`📡 API available at http://localhost:${PORT}`);
  });
}

startServer();
