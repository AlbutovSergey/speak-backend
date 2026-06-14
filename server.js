const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());

// ============ ВРЕМЕННАЯ ЗАГЛУШКА (без базы данных) ============
// Хранилище пользователей в памяти (временно!)
const users = new Map();

function generateSessionToken(userId) {
  const randomPart = crypto.randomBytes(32).toString('hex');
  return `${userId}.${randomPart}`;
}

// РЕГИСТРАЦИЯ
app.post("/api/register", async (req, res) => {
  try {
    const { username, password, displayName, publicKey, signaturePublicKey, signaturePrivateKey } = req.body;
    
    if (!username || !password || !displayName) {
      return res.status(400).json({ error: "All fields required" });
    }
    
    if (users.has(username)) {
      return res.status(409).json({ error: "Username already exists" });
    }
    
    const userId = crypto.randomBytes(16).toString('hex');
    users.set(username, { userId, username, displayName, password });
    
    const token = generateSessionToken(userId);
    
    res.json({ 
      success: true, 
      token, 
      userId, 
      username, 
      displayName 
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ЛОГИН
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const user = users.get(username);
    if (!user || user.password !== password) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    
    const token = generateSessionToken(user.userId);
    
    res.json({ 
      success: true, 
      token, 
      userId: user.userId, 
      username: user.username, 
      display_name: user.displayName,
      signature_private_key: 'temp-private-key'
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ПОЛУЧИТЬ ПУБЛИЧНЫЙ КЛЮЧ
app.get("/api/public_key/:username", async (req, res) => {
  res.json({ public_key: 'test-public-key' });
});

// ПОЛУЧИТЬ СООБЩЕНИЯ
app.get("/api/messages", (req, res) => {
  res.json([]);
});

// ОТПРАВИТЬ СООБЩЕНИЕ
app.post("/api/send_message", (req, res) => {
  res.json({ success: true });
});

// ПРОВЕРКА ТОКЕНА
app.get("/api/verify", (req, res) => {
  res.json({ valid: true });
});

// ВЫХОД
app.post("/api/logout", (req, res) => {
  res.json({ success: true });
});

app.get("/", (req, res) => {
  res.json({ status: "Speak server is running (test mode)", version: "2.0-test" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Speak server running on port ${PORT} (test mode)`));
