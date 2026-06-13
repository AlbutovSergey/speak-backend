// ============ НОВЫЕ ЭНДПОИНТЫ ДЛЯ ПСЕВДОНИМОВ ============

// 1. Регистрация с псевдонимом (обновляем существующий эндпоинт)
// Найдите в коде app.post("/api/register", ...) и ЗАМЕНИТЕ его на этот:
app.post("/api/register", async (req, res) => {
  const { username, password, displayName, publicKey, signaturePublicKey, signaturePrivateKey } = req.body;
  
  // Валидация
  if (!username || !password || !displayName || !publicKey || !signaturePublicKey || !signaturePrivateKey) {
    return res.status(400).json({ error: "All fields are required" });
  }
  
  if (username.length < 3) {
    return res.status(400).json({ error: "Username must be at least 3 characters" });
  }
  
  if (displayName.length < 1 || displayName.length > 50) {
    return res.status(400).json({ error: "Display name must be 1-50 characters" });
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
      `INSERT INTO users_auth(id, username, password_hash, display_name, public_key, signature_public_key, signature_private_key, created_at)
       VALUES($1, $2, $3, $4, $5, $6, $7, $8)`,
      [userId, username, `${hash}.${salt}`, displayName, publicKey, signaturePublicKey, signaturePrivateKey, Date.now()]
    );
    
    // Создаём сессию
    const token = generateSessionToken(userId);
    const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
    await pool.query(
      'INSERT INTO sessions(token, user_id, expires_at, created_at) VALUES($1, $2, $3, $4)',
      [token, userId, expiresAt, Date.now()]
    );
    
    res.json({ 
      success: true, 
      token, 
      userId,
      username,
      displayName,
      message: "Registration successful"
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// 2. Получение публичных данных пользователя (с псевдонимом)
app.get("/api/user_info/:username", async (req, res) => {
  const { username } = req.params;
  const result = await pool.query(
    "SELECT id, username, display_name, public_key, signature_public_key FROM users_auth WHERE username = $1",
    [username]
  );
  if (result.rows.length === 0) {
    return res.status(404).json({ error: "User not found" });
  }
  res.json(result.rows[0]);
});

// 3. Получение пользователя по ID
app.get("/api/user_info_by_id/:userId", async (req, res) => {
  const { userId } = req.params;
  const result = await pool.query(
    "SELECT id, username, display_name, public_key FROM users_auth WHERE id = $1",
    [userId]
  );
  if (result.rows.length === 0) {
    return res.status(404).json({ error: "User not found" });
  }
  res.json(result.rows[0]);
});

// 4. Смена псевдонима (только авторизованные)
app.post("/api/change_display_name", authMiddleware, async (req, res) => {
  const { newDisplayName } = req.body;
  
  if (!newDisplayName || newDisplayName.length < 1 || newDisplayName.length > 50) {
    return res.status(400).json({ error: "Display name must be 1-50 characters" });
  }
  
  try {
    await pool.query(
      'UPDATE users_auth SET display_name = $1 WHERE id = $2',
      [newDisplayName, req.userId]
    );
    res.json({ success: true, displayName: newDisplayName });
  } catch (err) {
    console.error('Change display name error:', err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// 5. Получение списка контактов (с псевдонимами)
app.get("/api/contacts", authMiddleware, async (req, res) => {
  try {
    // Находим всех, с кем пользователь переписывался
    const result = await pool.query(
      `SELECT DISTINCT 
         u.id, u.username, u.display_name, u.public_key
       FROM messages m
       JOIN users_auth u ON (m.sender_id = u.id OR m.recipient_id = u.id)
       WHERE (m.sender_id = $1 OR m.recipient_id = $1)
         AND u.id != $1`,
      [req.userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Get contacts error:', err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// 6. Обновляем получение сообщений (возвращаем display_name)
app.get("/api/messages", authMiddleware, async (req, res) => {
  const result = await pool.query(
    `SELECT 
       m.sender_id, 
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
});
