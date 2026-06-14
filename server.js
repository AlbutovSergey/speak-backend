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
  idleTimeoutMillis: 30000,
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

// ============ MIDDLEWARE АВТОРИЗАЦИИ ============
async function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const result = await pool.query(
      'SELECT user_id, expires_at FROM sessions WHERE token = $1',
      [token]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    if (result.rows[0].expires_at < Date.now()) {
      await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
      return res.status(401).json({ error: 'Token expired' });
    }
    req.userId = result.rows[0].user_id;
    next();
  } catch (err) {
    console.error('Auth error:', err);
    res.status(500).json({ error: "Internal server error" });
  }
}

// ============ ИНИЦИАЛИЗАЦИЯ ТАБЛИЦ ============
async function initDatabase() {
  try {
    console.log('Checking database connection...');
    await pool.query('SELECT NOW()');
    console.log('✅ Database connected');
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users_auth (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        display_name TEXT NOT NULL DEFAULT '',
        public_key TEXT NOT NULL,
        signature_public_key TEXT NOT NULL,
        signature_private_key TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        last_login BIGINT
      )
    `);
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users_auth(id) ON DELETE CASCADE
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
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id)`);
    
    console.log('✅ Tables ready');
  } catch (err) {
    console.error('❌ Database init error:', err.message);
  }
}

// ============ API ЭНДПОИНТЫ ============

app.get("/", (req, res) => {
  res.json({ status: "Speak server is running", version: "2.0", timestamp: Date.now() });
});

// РЕГИСТРАЦИЯ
app.post("/api/register", async (req, res) => {
  try {
    const { username, password, displayName, publicKey, signaturePublicKey, signaturePrivateKey } = req.body;
    
    if (!username || !password || !displayName || !publicKey || !signaturePublicKey || !signaturePrivateKey) {
      return res.status(400).json({ error: "All fields required" });
    }
    
    if (username.length < 3) {
      return res.status(400).json({ error: "Username must be at least 3 characters" });
    }
    
    if (displayName.length < 2) {
      return res.status(400).json({ error: "Display name too short" });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }
    
    const existingUser = await pool.query('SELECT id FROM users_auth WHERE username = $1', [username]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: "Username already exists" });
    }
    
    const existingDisplayName = await pool.query('SELECT id FROM users_auth WHERE display_name = $1', [displayName]);
    if (existingDisplayName.rows.length > 0) {
      return res.status(409).json({ error: "This display name is already taken" });
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
    
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required" });
    }
    
    const result = await pool.query(
      'SELECT id, username, password_hash, display_name, public_key, signature_public_key, signature_private_key FROM users_auth WHERE username = $1',
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
    
    await pool.query('UPDATE users_auth SET last_login = $1 WHERE id = $2', [Date.now(), user.id]);
    await pool.query('DELETE FROM sessions WHERE user_id = $1 AND expires_at < $2', [user.id, Date.now()]);
    
    const token = generateSessionToken(user.id);
    const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
    await pool.query('INSERT INTO sessions(token, user_id, expires_at, created_at) VALUES($1, $2, $3, $4)', [token, user.id, expiresAt, Date.now()]);
    
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
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
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
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
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
      `SELECT id, username, display_name, public_key FROM users_auth WHERE display_name ILIKE $1 ORDER BY display_name ASC LIMIT 10`,
      [`%${q}%`]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Search error:', err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============ СООБЩЕНИЯ ============
// ПОЛУЧИТЬ СООБЩЕНИЯ
app.get("/api/messages", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT m.id, m.encrypted_payload, m.nonce, m.timestamp,
              u_sender.username as sender_username, 
              u_sender.display_name as sender_display_name,
              u_recipient.username as recipient_username
       FROM messages m
       JOIN users_auth u_sender ON m.sender_id = u_sender.id
       JOIN users_auth u_recipient ON m.recipient_id = u_recipient.id
       WHERE m.recipient_id = $1 OR m.sender_id = $1
       ORDER BY m.timestamp ASC`,
      [req.userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Get messages error:', err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ОТПРАВИТЬ СООБЩЕНИЕ
app.post("/api/send_message", authMiddleware, async (req, res) => {
  try {
    const { recipientUsername, encryptedPayload, nonce } = req.body;
    
    if (!recipientUsername || !encryptedPayload) {
      return res.status(400).json({ error: "Recipient and message required" });
    }
    
    const recipient = await pool.query('SELECT id FROM users_auth WHERE username = $1', [recipientUsername]);
    if (recipient.rows.length === 0) {
      return res.status(404).json({ error: "Recipient not found" });
    }
    
    await pool.query(
      `INSERT INTO messages(sender_id, recipient_id, encrypted_payload, nonce, timestamp)
       VALUES($1, $2, $3, $4, $5)`,
      [req.userId, recipient.rows[0].id, encryptedPayload, nonce || '', Date.now()]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Send message error:', err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ПРОВЕРКА ТОКЕНА
app.get("/api/verify", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, display_name FROM users_auth WHERE id = $1', [req.userId]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: "User not found" });
    }
    res.json({ valid: true, user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ВЫХОД
app.post("/api/logout", authMiddleware, async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;

async function startServer() {
  await initDatabase();
  app.listen(PORT, () => {
    console.log(`✅ Speak server running on port ${PORT}`);
    console.log(`📡 API available at http://localhost:${PORT}`);
  });
}

startServer();
