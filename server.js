require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

// Инициализация приложения
const app = express();
app.use(express.json());
app.use(cors());

// Подключение к MongoDB (использует переменную из Railway)
const mongoUrl = process.env.MONGO_URL || 'mongodb+srv://user:pass@cluster.mongodb.net/dbname?retryWrites=true&w=majority';
mongoose.connect(mongoUrl, { 
  useNewUrlParser: true, 
  useUnifiedTopology: true 
})
.then(() => console.log('✅ MongoDB connected'))
.catch(err => console.log('❌ MongoDB error:', err.message));

// Модель пользователя
const User = mongoose.model('User', new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  loginPassword: { type: String, required: true },
  withdrawPassword: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
}));

// Middleware для проверки токена
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret');
    req.user = decoded;
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
