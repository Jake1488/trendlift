const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Подключение к MongoDB (замените на свой URL!)
const mongoUrl = process.env.MONGO_URL || 'mongodb+srv://username:password@cluster.mongodb.net/dbname?retryWrites=true&w=majority';

mongoose.connect(mongoUrl)
  .then(() => console.log('MongoDB подключен!'))
  .catch(err => console.log('Ошибка MongoDB:', err));

// Модель пользователя
const User = mongoose.model('User', {
  username: { type: String, unique: true },
  loginPassword: String,
  withdrawPassword: String
});

// Здесь добавьте роуты (/api/register, /api/login) как в предыдущих примерах

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Сервер запущен на порту ${PORT}`));
