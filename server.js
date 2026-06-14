const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());

// Временное хранилище в памяти
const users = new Map();

app.get("/", (req, res) => {
  res.json({ status: "Speak server is running", version: "2.0-test" });
});

// Регистрация
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
    users.set(username, { userId, username, displayName, password });
    
    const token = crypto.randomBytes(32).toString('hex');
    
    res.json({ 
      success: true, 
      token, 
      userId, 
      username, 
      displayName 
    });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Логин
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
      signature_private_key: "temp-private-key"
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Публичный ключ
app.get("/api/public_key/:username", async (req, res) => {
  res.json({ public_key: "test-public-key" });
});

// Сообщения
app.get("/api/messages", (req, res) => {
  res.json([]);
});

app.post("/api/send_message", (req, res) => {
  res.json({ success: true });
});

app.get("/api/verify", (req, res) => {
  res.json({ valid: true });
});

app.post("/api/logout", (req, res) => {
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Speak server running on port ${PORT}`));
