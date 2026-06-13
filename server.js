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

// ============ ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ============

// Хеширование пароля (PBKDF2)
async function hashPassword(password, salt = null) {
  if (!salt) {
    salt = crypto.randomBytes(16).toString('hex');
  }
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, 100000, 64, 'sha512', (err, derivedKey) => {
      if (err) reject(err);
      resolve({ hash: derivedKey.toString('hex'), salt });
    });
  });
}

// Проверка пароля
async function verifyPassword(password, hash, salt) {
  const { hash: testHash } = await hashPassword(password, salt);
  return testHash === hash;
}

// Генерация токена сессии
function generateSessionToken(userId) {
  const randomPart = crypto.randomBytes(32).toString('hex');
  const signature = crypto.createHmac('sha256', process.env.SESSION_SECRET || 'speak_secret')
    .update(userId + randomPart)
    .digest('hex');
  return `${userId}.${randomPart}.${signature}`;
}

// Проверка токена
async function verifySessionToken(token) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [userId, randomPart, signature] = parts;
  
  const expectedSignature = crypto.createHmac('sha256', process.env.SESSION_SECRET || 'speak_secret')
    .update(userId + randomPart)
    .digest('hex');
  
  if (signature !== expectedSignature) return null;
  
  // Проверяем в БД
  const result = await pool.query(
    'SELECT user_id, expires_at FROM sessions WHERE token = $1',
    [token]
  );
  
  if (result.rows.length === 0) return null;
  if (result.rows[0].expires_at < Date.now()) {
    await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
    return null;
  }
  
  return result.rows[0].user_id;
}

// Middleware для проверки авторизации
async function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  const userId = await verifySessionToken(token);
  if (!userId) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  
  req.userId = userId;
  next();
}

// ============ API ЭНДПОИНТЫ ============

// Корневой эндпоинт для проверки
app.get("/", (req, res) => {
  res.json({ status: "Speak server is running", version: "2.0" });
});

// РЕГИСТРАЦИЯ
app.post("/api/register", async (req, res) => {
  const { username, password, publicKey, signaturePublicKey, signaturePrivateKey } = req.body;
  
  // Валидация
  if (!username || !password || !publicKey || !signaturePublicKey || !signaturePrivateKey) {
    return res.status(400).json({ error: "All fields are required" });
  }
  
  if (username.length < 3) {
    return res.status(400).json({ error: "Username must be at least 3 characters" });
  }
  
  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  }
  
  try {
    // Проверяем, не занят ли username
    const existing = await pool.query('SELECT id FROM users_auth WHERE username = $1', [username]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: "Username already exists" });
    }
    
    // Хешируем пароль
    const { hash, salt } = await hashPassword(password);
    
    // Создаём пользователя
    const userId = crypto.randomBytes(16).toString('hex');
    await pool.query(
      `INSERT INTO users_auth(id, username, password_hash, public_key, signature_public_key, signature_private_key, created_at)
       VALUES($1, $2, $3, $4, $5, $6, $7)`,
      [userId, username, `${hash}.${salt}`, publicKey, signaturePublicKey, signaturePrivateKey, Date.now()]
    );
    
    // Создаём сессию
    const token = generateSessionToken(userId);
    const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7 дней
    await pool.query(
      'INSERT INTO sessions(token, user_id, expires_at, created_at) VALUES($1, $2, $3, $4)',
      [token, userId, expiresAt, Date.now()]
    );
    
    res.json({ 
      success: true, 
      token, 
      userId,
      username,
      message: "Registration successful"
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// АВТОРИЗАЦИЯ (ЛОГИН)
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }
  
  try {
    // Ищем пользователя
    const result = await pool.query(
      'SELECT id, username, password_hash, public_key, signature_public_key, signature_private_key FROM users_auth WHERE username = $1',
      [username]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid username or password" });
    }
    
    const user = result.rows[0];
    const [hash, salt] = user.password_hash.split('.');
    
    // Проверяем пароль
    const isValid = await verifyPassword(password, hash, salt);
    if (!isValid) {
      return res.status(401).json({ error: "Invalid username or password" });
    }
    
    // Обновляем last_login
    await pool.query('UPDATE users_auth SET last_login = $1 WHERE id = $2', [Date.now(), user.id]);
    
    // Удаляем старые сессии (опционально)
    await pool.query('DELETE FROM sessions WHERE user_id = $1 AND expires_at < $2', [user.id, Date.now()]);
    
    // Создаём новую сессию
    const token = generateSessionToken(user.id);
    const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
    await pool.query(
      'INSERT INTO sessions(token, user_id, expires_at, created_at) VALUES($1, $2, $3, $4)',
      [token, user.id, expiresAt, Date.now()]
    );
    
    res.json({ 
      success: true, 
      token,
      userId: user.id,
      username: user.username,
      publicKey: user.public_key,
      signaturePublicKey: user.signature_public_key,
      signaturePrivateKey: user.signature_private_key
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ВЫХОД ИЗ СИСТЕМЫ
app.post("/api/logout", authMiddleware, async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
  res.json({ success: true, message: "Logged out" });
});

// ПРОВЕРКА ТОКЕНА (валидна ли сессия)
app.get("/api/verify", authMiddleware, async (req, res) => {
  const result = await pool.query(
    'SELECT id, username, public_key, signature_public_key FROM users_auth WHERE id = $1',
    [req.userId]
  );
  if (result.rows.length === 0) {
    return res.status(401).json({ error: "User not found" });
  }
  res.json({ valid: true, user: result.rows[0] });
});

// ПОЛУЧИТЬ ПУБЛИЧНЫЙ КЛЮЧ ПОЛЬЗОВАТЕЛЯ ПО USERNAME
app.get("/api/public_key/:username", async (req, res) => {
  const { username } = req.params;
  const result = await pool.query(
    "SELECT public_key, signature_public_key FROM users_auth WHERE username = $1",
    [username]
  );
  if (result.rows.length === 0) {
    return res.status(404).json({ error: "User not found" });
  }
  res.json(result.rows[0]);
});

// ПОЛУЧИТЬ ID ПОЛЬЗОВАТЕЛЯ ПО USERNAME
app.get("/api/user_id/:username", async (req, res) => {
  const { username } = req.params;
  const result = await pool.query(
    "SELECT id FROM users_auth WHERE username = $1",
    [username]
  );
  if (result.rows.length === 0) {
    return res.status(404).json({ error: "User not found" });
  }
  res.json({ userId: result.rows[0].id });
});

// ОТПРАВИТЬ СООБЩЕНИЕ (с авторизацией)
app.post("/api/send_message", authMiddleware, async (req, res) => {
  const { recipientUsername, encryptedPayload, nonce } = req.body;
  
  // Получаем ID получателя по username
  const recipientResult = await pool.query(
    'SELECT id FROM users_auth WHERE username = $1',
    [recipientUsername]
  );
  if (recipientResult.rows.length === 0) {
    return res.status(404).json({ error: "Recipient not found" });
  }
  
  const recipientId = recipientResult.rows[0].id;
  
  await pool.query(
    `INSERT INTO messages(sender_id, recipient_id, encrypted_payload, nonce, timestamp)
     VALUES($1, $2, $3, $4, $5)`,
    [req.userId, recipientId, encryptedPayload, nonce, Date.now()]
  );
  res.json({ success: true });
});

// ПОЛУЧИТЬ СООБЩЕНИЯ
app.get("/api/messages", authMiddleware, async (req, res) => {
  const result = await pool.query(
    `SELECT m.sender_id, u.username as sender_username, m.encrypted_payload, m.nonce, m.timestamp
     FROM messages m
     JOIN users_auth u ON m.sender_id = u.id
     WHERE m.recipient_id = $1
     ORDER BY m.timestamp ASC`,
    [req.userId]
  );
  res.json(result.rows);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Speak server running on port ${PORT}`));
