const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Подключение к PostgreSQL (Render создаст DATABASE_URL автоматически)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Создаем таблицу пользователей (выполнится при старте)
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      login_password VARCHAR(100) NOT NULL,
      withdraw_password VARCHAR(100) NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
}

// Регистрация
app.post('/api/register', async (req, res) => {
  try {
    const { username, loginPassword, withdrawPassword } = req.body;

    // Проверка данных
    if (!username || !loginPassword || !withdrawPassword) {
      return res.status(400).json({ error: 'Все поля обязательны' });
    }

    // Шифруем пароли
    const hashedLoginPassword = await bcrypt.hash(loginPassword, 10);
    const hashedWithdrawPassword = await bcrypt.hash(withdrawPassword, 10);

    // Сохраняем в БД
    await pool.query(
      'INSERT INTO users (username, login_password, withdraw_password) VALUES ($1, $2, $3)',
      [username, hashedLoginPassword, hashedWithdrawPassword]
    );

    res.status(201).json({ message: 'Пользователь создан!' });

  } catch (err) {
    if (err.code === '23505') {
      return res.status(400).json({ error: 'Имя пользователя занято' });
    }
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Вход
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Ищем пользователя
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.login_password))) {
      return res.status(401).json({ error: 'Неверные данные' });
    }

    // Генерируем токен
    const token = jwt.sign(
      { username },
      process.env.JWT_SECRET || 'secret_fallback',
      { expiresIn: '1h' }
    );

    res.json({ token });

  } catch (err) {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Инициализация и запуск
initDB().then(() => {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
  });
});    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

// Роуты
app.post('/api/register', async (req, res) => {
  try {
    const { username, loginPassword, withdrawPassword } = req.body;

    // Валидация
    if (!username || !loginPassword || !withdrawPassword) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Проверка существующего пользователя
    if (await User.findOne({ username })) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    // Хеширование паролей
    const hashedLoginPassword = await bcrypt.hash(loginPassword, 10);
    const hashedWithdrawPassword = await bcrypt.hash(withdrawPassword, 10);

    // Создание пользователя
    const user = new User({
      username,
      loginPassword: hashedLoginPassword,
      withdrawPassword: hashedWithdrawPassword
    });

    await user.save();
    res.status(201).json({ message: 'User registered successfully' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Поиск пользователя
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Проверка пароля
    const isMatch = await bcrypt.compare(password, user.loginPassword);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Генерация токена
    const token = jwt.sign(
      { username: user.username },
      process.env.JWT_SECRET || 'fallback_secret',
      { expiresIn: '1h' }
    );

    res.json({ token });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/profile', authenticate, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    res.json({
      username: user.username,
      createdAt: user.createdAt
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Запуск сервера
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

// "Keep alive" для Railway
setInterval(() => {
  console.log('🫀 Heartbeat');
}, 60000);
