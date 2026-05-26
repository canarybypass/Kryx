#!/bin/bash
set -e

echo "=== Mythos Setup ==="

# Запрашиваем ключ
read -p "Вставь Gemini API Key: " API_KEY

# Создаём .env
echo "GEMINI_API_KEY=$API_KEY" > backend/.env

# Устанавливаем Python зависимости
echo "Устанавливаю backend зависимости..."
cd backend
pip install -r requirements.txt -q
cd ..

# Устанавливаем frontend зависимости
echo "Устанавливаю frontend зависимости..."
cd frontend
npm install --silent
cd ..

echo ""
echo "=== Запускаю ==="

# Запускаем backend в фоне
cd backend
python main.py &
BACKEND_PID=$!
cd ..

sleep 2

# Запускаем frontend
cd frontend
npm start &
FRONTEND_PID=$!
cd ..

echo ""
echo "✅ Готово! Открывай: http://localhost:3000"
echo "Для остановки нажми Ctrl+C"

# Ждём Ctrl+C
trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" INT
wait
