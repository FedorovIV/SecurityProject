import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

const app = express();
const PORT = 3000;

// Указываем IPv6 адрес, например, '::' для всех IPv6 интерфейсов
const HOST = '::';

// Абсолютный путь к статическим файлам
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDirectory = path.join(__dirname, 'public');

// Раздача статических файлов
app.use(express.static(publicDirectory));

// Маршрут для проверки
app.get('/', (req, res) => {
  res.send('Сервер запущен на IPv6!');
});

// Запуск сервера
app.listen(PORT, HOST, () => {
  console.log(`Сервер работает по адресу http://[${HOST}]:${PORT}`);
});
