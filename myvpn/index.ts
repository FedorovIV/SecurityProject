import express from "express";
import { createProxyMiddleware } from 'http-proxy-middleware';

const app = express();
const PORT = 3000;

// Целевой сервер, на который будет перенаправляться трафик
const TARGET_URL = 'https://jsonplaceholder.typicode.com';

// Использование прокси для всех запросов к "/api"
app.use(
  '/api',
  createProxyMiddleware({
    target: TARGET_URL, // Адрес целевого сервера
    changeOrigin: true, // Меняет "Origin" на целевой сервер
    pathRewrite: {
      '^/api': '', // Убирает префикс /api перед отправкой на целевой сервер
    },
  })
);

// Запуск сервера
app.listen(PORT, () => {
  console.log(`Прокси-сервер запущен на http://localhost:${PORT}`);
});
