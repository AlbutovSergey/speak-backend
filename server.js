const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());

// Временное хранилище в памяти (пока нет базы данных)
const users = new Map();

app.get("/", (req, res) => {
  res.json({ status: "Speak server is running", version: "2.0-test" });
});

// ============ РЕГИСТРАЦИЯ ============
app.post("/api/register", async (req, res) => {
  try {
    const { username, password, displayName, publicKey, signaturePublicKey, signaturePrivateKey } = req.body;
    
    console.log("Register attempt:", username);
    
    if (!username || !password || !displayName) {
      return res.status(400).json({ error: "All fields required" });
    }
    
    if (username.length < 3) {
      return res.status(400).json({ error: "Username too short" });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: "Password too short" });
    }
    
    if (users.has(username)) {
      return res.status(409).json({ error: "Username already exists" });
    }
    
    const userId = crypto.randomBytes(16).toString('hex');
    users.set(username, { 
      userId, 
      username, 
      displayName: displayName || username, 
      password,
      publicKey: publicKey || 'temp-key',
      signaturePublicKey: signaturePublicKey || 'temp-sig',
      signaturePrivateKey: signaturePrivateKey || 'temp-priv'
    });
    
    const token = crypto.randomBytes(32).toString('hex');
    
    console.log("User registered:", username);
    
    res.json({ 
      success: true, 
      token, 
      userId, 
      username, 
      displayName: displayName || username 
    });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============ ЛОГИН ============
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    
    console.log("Login attempt:", username);
    
    const user = users.get(username);
    if (!user || user.password !== password) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    
    const token = crypto.randomBytes(32).toString('hex');
    
    res.json({ 
      success: true, 
      token, 
      userId: user.userId, 
      username: user.username, 
      display_name: user.displayName,
      signature_private_key: user.signaturePrivateKey || "temp-private-key"
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============ ПОЛУЧИТЬ ПУБЛИЧНЫЙ КЛЮЧ ============
app.get("/api/public_key/:username", async (req, res) => {
  try {
    const { username } = req.params;
    const user = users.get(username);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json({ public_key: user.publicKey || "test-public-key" });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============ ПОЛУЧИТЬ ИНФОРМАЦИЮ О ПОЛЬЗОВАТЕЛЕ ============
app.get("/api/user_info/:username", async (req, res) => {
  try {
    const { username } = req.params;
    const user = users.get(username);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json({ 
      id: user.userId, 
      username: user.username, 
      display_name: user.displayName,
      public_key: user.publicKey
    });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============ ПОИСК ПОЛЬЗОВАТЕЛЕЙ ПО ОТОБРАЖАЕМОМУ ИМЕНИ ============
app.get("/api/users/search", async (req, res) => {
  try {
    const { q } = req.query;
    
    if (!q || q.length < 2) {
      return res.json([]);
    }
    
    const searchLower = q.toLowerCase();
    const results = [];
    
    for (const [username, user] of users) {
      const displayName = user.displayName || username;
      const displayNameLower = displayName.toLowerCase().replace(/^@/, '');
      
      if (displayNameLower.includes(searchLower) || username.toLowerCase().includes(searchLower)) {
        if (username !== users.get('currentUser')) {
          results.push({
            id: user.userId,
            username: user.username,
            display_name: user.displayName || user.username,
            public_key: user.publicKey
          });
        }
      }
    }
    
    res.json(results.slice(0, 10));
  } catch (err) {
    console.error('Search users error:', err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============ СООБЩЕНИЯ ============
app.get("/api/messages", (req, res) => {
  res.json([]);
});

app.post("/api/send_message", (req, res) => {
  res.json({ success: true });
});

app.get("/api/verify", (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  res.json({ valid: !!token });
});

app.post("/api/logout", (req, res) => {
  res.json({ success: true });
});

// ============ ЗАПУСК ============
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Speak server running on port ${PORT}`));
