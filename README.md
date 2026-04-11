# Контрольная работа №3 — FastAPI серверное приложение

## Установка зависимостей

```bash
pip install -r requirements.txt
```

## Запуск приложения

```bash
uvicorn main:app --reload
```

По умолчанию приложение запустится на `http://localhost:8000`.

## Переменные окружения

Создайте файл `.env` на основе `.env.example`:

```bash
cp .env.example .env
```

Основные переменные:
- `MODE` — режим работы: `DEV` (документация доступна) или `PROD` (документация скрыта)
- `DOCS_USER` / `DOCS_PASSWORD` — учётные данные для доступа к `/docs` в DEV-режиме
- `JWT_SECRET` — секретный ключ для подписи JWT токенов

## Тестирование эндпоинтов

### Задание 6.1 — Простая базовая аутентификация

```bash
# Успешный логин
curl -u testuser:testpass http://localhost:8000/login_simple

# Неверный пароль (401)
curl -u testuser:wrongpass http://localhost:8000/login_simple
```

### Задание 6.2 — Регистрация и логин с хешированием паролей

```bash
# Регистрация
curl -X POST -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"correctpass"}' \
  http://localhost:8000/register

# Успешный логин
curl -u user1:correctpass http://localhost:8000/login

# Неверный пароль (401)
curl -u user1:wrongpass http://localhost:8000/login
```

### Задание 6.4 — JWT аутентификация (заглушка)

```bash
# Логин (заглушка — случайный ответ)
curl -X POST -H "Content-Type: application/json" \
  -d '{"username":"john_doe","password":"securepassword123"}' \
  http://localhost:8000/login_jwt
```

### Задание 6.5 — Полный JWT логин (после регистрации)

```bash
# Сначала зарегистрируйте пользователя через /register
# Затем войдите через /login (POST)

curl -X POST -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"qwerty123"}' \
  http://localhost:8000/register

# Логин с получением JWT токена
curl -X POST -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"qwerty123"}' \
  http://localhost:8000/login

# Доступ к защищённому ресурсу
curl -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  http://localhost:8000/protected_resource_jwt
```

### Задание 7.1 — RBAC (управление доступом по ролям)

```bash
# Защищённый ресурс (требует роль user или выше)
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8000/protected_resource

# Ресурс только для admin
curl -H "Authorization: Bearer YOUR_TOKEN" \
  -X POST http://localhost:8000/admin_only_resource
```

### Задание 8.1 — Регистрация через SQLite

```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"username":"test_user","password":"12345"}' \
  http://localhost:8000/register_db
```

### Задание 8.2 — CRUD для Todo

```bash
# Создание
curl -X POST -H "Content-Type: application/json" \
  -d '{"title":"Buy groceries","description":"Milk, eggs, bread"}' \
  http://localhost:8000/todos

# Чтение
curl http://localhost:8000/todos/1

# Обновление
curl -X PUT -H "Content-Type: application/json" \
  -d '{"title":"Updated title","completed":true}' \
  http://localhost:8000/todos/1

# Удаление
curl -X DELETE http://localhost:8000/todos/1
```

## Документация API

- DEV режим: `http://localhost:8000/docs` (требует аутентификацию)
- PROD режим: документация недоступна (возвращает 404)
