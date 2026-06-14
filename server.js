const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());

// Временное хранилище в памяти
const users = new Map();
const messages = [];

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
      signature_private_key: user.signaturePrivateKey
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============ ПОЛУЧИТЬ ПУБЛИЧНЫЙ КЛЮЧ ============
app.get("/api/public_key/:username", async (req, res) => {
  const { username } = req.params;
  const user = users.get(username);
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }
  res.json({ public_key: user.publicKey });
});

// ============ ПОЛУЧИТЬ ИНФОРМАЦИЮ О ПОЛЬЗОВАТЕЛЕ ============
app.get("/api/user_info/:username", async (req, res) => {
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
});

// ============ ПОИСК ПОЛЬЗОВАТЕЛЕЙ ============
app.get("/api/users/search", async (req, res) => {
  const { q } = req.query;
  if (!q || q.length < 2) {
    return res.json([]);
  }
  
  const searchLower = q.toLowerCase();
  const results = [];
  
  for (const [username, user] of users) {
    const displayName = (user.displayName || username).toLowerCase().replace(/^@/, '');
    if (displayName.includes(searchLower) || username.toLowerCase().includes(searchLower)) {
      results.push({
        id: user.userId,
        username: user.username,
        display_name: user.displayName || user.username,
        public_key: user.publicKey
      });
    }
  }
  
  res.json(results.slice(0, 10));
});

// ============ ОТПРАВИТЬ СООБЩЕНИЕ ============
app.post("/api/send_message", (req, res) => {
  const { recipientUsername, encryptedPayload, nonce } = req.body;
  const authHeader = req.headers.authorization;
  
  let senderUsername = null;
  for (const [username, user] of users) {
    if (authHeader && authHeader.includes(user.userId)) {
      senderUsername = username;
      break;
    }
  }
  
  if (!senderUsername) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  
  messages.push({
    id: messages.length + 1,
    sender_username: senderUsername,
    recipient_username: recipientUsername,
    encrypted_payload: encryptedPayload,
    nonce: nonce || '',
    timestamp: Date.now()
  });
  
  res.json({ success: true });
});

// ============ ПОЛУЧИТЬ СООБЩЕНИЯ ============
app.get("/api/messages", (req, res) => {
  const authHeader = req.headers.authorization;
  let currentUser = null;
  
  for (const [username, user] of users) {
    if (authHeader && authHeader.includes(user.userId)) {
      currentUser = username;
      break;
    }
  }
  
  if (!currentUser) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  
  const userMessages = messages.filter(msg => 
    msg.recipient_username === currentUser || 
    msg.sender_username === currentUser
  );
  
  const result = userMessages.map(msg => {
    const sender = users.get(msg.sender_username);
    return {
      id: msg.id,
      sender_username: msg.sender_username,
      sender_display_name: sender?.displayName || msg.sender_username,
      encrypted_payload: msg.encrypted_payload,
      nonce: msg.nonce,
      timestamp: msg.timestamp
    };
  });
  
  res.json(result);
});

// ============ ПРОВЕРКА ТОКЕНА ============
app.get("/api/verify", (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  let valid = false;
  
  for (const [username, user] of users) {
    if (token && token.includes(user.userId)) {
      valid = true;
      break;
    }
  }
  
  res.json({ valid });
});

// ============ ВЫХОД ============
app.post("/api/logout", (req, res) => {
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Speak server running on port ${PORT}`));
