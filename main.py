import os
import secrets
import time
import random
import bcrypt
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials
from pydantic_settings import BaseSettings
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from database import get_db_connection, init_db
from models import (
    UserBase, User, UserInDB,
    LoginRequest, TokenResponse,
    UserWithRole, UserInDBWithRole,
    TodoCreate, TodoUpdate, TodoResponse,
)

# ============================================================
# Конфигурация окружения
# ============================================================

class Settings(BaseSettings):
    MODE: str = "DEV"  # DEV или PROD
    DOCS_USER: str = "admin"
    DOCS_PASSWORD: str = "adminpass"
    JWT_SECRET: str = "my_secret_key_change_in_production"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    class Config:
        env_file = ".env"

settings = Settings()

if settings.MODE not in ("DEV", "PROD"):
    raise ValueError(f"Недопустимое значение MODE: {settings.MODE}. Допустимые: DEV, PROD")

# ============================================================
# Инициализация приложения
# ============================================================

# В PROD документация отключена
if settings.MODE == "PROD":
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
else:
    app = FastAPI(docs_url="/docs", redoc_url="/redoc", openapi_url="/openapi.json")

# Rate Limiter (Задание 6.5)
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ============================================================
# Задание 6.2: Хеширование паролей через bcrypt напрямую
# ============================================================


def hash_password(password: str) -> str:
    """Хеширует пароль с помощью bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверяет пароль через bcrypt."""
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8"),
    )

# ============================================================
# In-memory база пользователей (для заданий 6.1-6.5)
# ============================================================

fake_users_db: dict[str, dict] = {}

# ============================================================
# Роли пользователей (Задание 7.1)
# ============================================================

ROLE_PERMISSIONS = {
    "admin": {"read": True, "write": True, "delete": True, "update": True},
    "user": {"read": True, "write": False, "delete": False, "update": True},
    "guest": {"read": True, "write": False, "delete": False, "update": False},
}

# ============================================================
# Задание 6.1: Простая базовая аутентификация
# ============================================================

security_simple = HTTPBasic()

# Простые учётные данные для задания 6.1
SIMPLE_USERS = {
    "testuser": "testpass",
}


def authenticate_simple(credentials: HTTPBasicCredentials) -> str:
    """Проверяет учётные данные для простой аутентификации (Задание 6.1)."""
    correct_username = SIMPLE_USERS.get(credentials.username)
    if correct_username is None or credentials.password != correct_username:
        # Проверяем точное совпадение password
        correct_pass = SIMPLE_USERS.get(credentials.username)
        if credentials.password != correct_pass:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Basic"},
            )
    return credentials.username


def authenticate_simple_fixed(credentials: HTTPBasicCredentials) -> str:
    """Исправленная версия простой аутентификации."""
    stored_password = SIMPLE_USERS.get(credentials.username)
    if stored_password is None or not secrets.compare_digest(
        credentials.password.encode(), stored_password.encode()
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


@app.get("/login_simple")
async def login_simple(credentials: HTTPBasicCredentials = Depends(security_simple)):
    """
    Задание 6.1: Защищённая конечная точка с базовой аутентификацией.
    GET /login_simple
    """
    username = authenticate_simple_fixed(credentials)
    return {"message": "You got my secret, welcome"}


# ============================================================
# Задание 6.2: Аутентификация с хешированием паролей
# ============================================================

security = HTTPBasic()


def auth_user(credentials: HTTPBasicCredentials = Depends(security)):
    """
    Зависимость аутентификации (Задание 6.2):
    - Извлекает username/password из HTTPBasicCredentials
    - Находит пользователя в fake_users_db
    - Проверяет пароль через verify()
    - Использует secrets.compare_digest() для username
    """
    # Безопасное сравнение username для защиты от тайминг-атак
    matching_username = None
    for username in fake_users_db:
        if secrets.compare_digest(username.encode(), credentials.username.encode()):
            matching_username = username
            break

    if matching_username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    user_data = fake_users_db[matching_username]
    if not verify_password(credentials.password, user_data["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    return UserInDB(username=matching_username, hashed_password=user_data["hashed_password"])


@app.post("/register")
@limiter.limit("1/minute")
async def register(request: Request, user: User):
    """
    Задание 6.2/6.5: Регистрация пользователя с хешированием пароля.
    Rate limit: 1 запрос в минуту.
    """
    # Проверяем, существует ли пользователь
    for username in fake_users_db:
        if secrets.compare_digest(username.encode(), user.username.encode()):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User already exists",
            )

    hashed_password = hash_password(user.password)
    fake_users_db[user.username] = {
        "username": user.username,
        "hashed_password": hashed_password,
        "role": "user",  # по умолчанию
    }

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={"message": "New user created"},
    )


@app.get("/login")
@limiter.limit("5/minute")
async def login(
    request: Request,
    current_user: UserInDB = Depends(auth_user),
):
    """
    Задание 6.2/6.5: Логин с хешированием паролей.
    Rate limit: 5 запросов в минуту.
    """
    return {"message": f"Welcome, {current_user.username}!"}


# ============================================================
# Задание 6.3: Защита документации в зависимости от MODE
# ============================================================

if settings.MODE == "DEV":
    docs_security = HTTPBasic()

    def verify_docs_credentials(credentials: HTTPBasicCredentials = Depends(docs_security)):
        """Проверка учётных данных для доступа к документации."""
        is_correct_user = secrets.compare_digest(
            credentials.username.encode(), settings.DOCS_USER.encode()
        )
        is_correct_pass = secrets.compare_digest(
            credentials.password.encode(), settings.DOCS_PASSWORD.encode()
        )
        if not (is_correct_user and is_correct_pass):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials for docs access",
                headers={"WWW-Authenticate": "Basic"},
            )
        return credentials.username

    # Переопределяем /docs с защитой
    @app.get("/docs", include_in_schema=False, dependencies=[Depends(verify_docs_credentials)])
    async def get_documentation():
        from fastapi.openapi.docs import get_swagger_ui_html
        return get_swagger_ui_html(openapi_url="/openapi.json", title="API Docs")

    # Переопределяем /openapi.json с защитой
    @app.get("/openapi.json", include_in_schema=False, dependencies=[Depends(verify_docs_credentials)])
    async def get_openapi():
        return app.openapi()

    # Переопределяем /redoc — скрыт (возвращаем 404)
    @app.get("/redoc", include_in_schema=False)
    async def get_redoc():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

elif settings.MODE == "PROD":
    # В PROD всё скрыто — возвращаем 404
    @app.get("/docs", include_in_schema=False)
    async def get_docs_prod():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    @app.get("/openapi.json", include_in_schema=False)
    async def get_openapi_prod():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    @app.get("/redoc", include_in_schema=False)
    async def get_redoc_prod():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


# ============================================================
# Задание 6.4: JWT аутентификация
# ============================================================

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Создаёт JWT токен."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Декодирует и проверяет JWT токен."""
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# Заглушка authenticate_user (Задание 6.4)
def authenticate_user(username: str, password: str) -> bool:
    """Заглушка: случайный True/False (для задания 6.4)."""
    return random.choice([True, False])


@app.post("/login_jwt", response_model=TokenResponse)
async def login_jwt(login_data: LoginRequest):
    """
    Задание 6.4: JWT аутентификация.
    POST /login_jwt — возвращает JWT токен.
    """
    # Используем заглушку (как указано в задании)
    if not authenticate_user(login_data.username, login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    access_token = create_access_token(data={"sub": login_data.username})
    return TokenResponse(access_token=access_token)


oauth2_scheme = HTTPBearer()


@app.get("/protected_resource_jwt")
async def protected_resource_jwt(credentials: HTTPAuthorizationCredentials = Depends(oauth2_scheme)):
    """
    Задание 6.4: Защищённый ресурс с JWT.
    GET /protected_resource_jwt — требует Bearer токен.
    """
    token = credentials.credentials
    payload = decode_access_token(token)
    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )
    return {"message": f"Access granted for user: {username}"}


# ============================================================
# Задание 6.5: Улучшенная JWT с регистрацией и Rate Limiting
# ============================================================

@app.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
async def login_jwt_full(request: Request, login_data: LoginRequest):
    """
    Задание 6.5: Полный логин с проверкой по базе fake_users_db.
    - 404 если пользователя нет
    - 401 если пароль неверный
    - 200 с JWT токеном при успехе
    Rate limit: 5 запросов в минуту.
    """
    # Безопасный поиск пользователя
    found_user = None
    for username in fake_users_db:
        if secrets.compare_digest(username.encode(), login_data.username.encode()):
            found_user = fake_users_db[username]
            break

    if found_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if not verify_password(login_data.password, found_user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization failed",
        )

    access_token = create_access_token(data={"sub": login_data.username})
    return TokenResponse(access_token=access_token)


# ============================================================
# Задание 7.1: RBAC — управление доступом на основе ролей
# ============================================================

def get_current_user_from_token(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())) -> dict:
    """Извлекает пользователя из JWT токена."""
    payload = decode_access_token(credentials.credentials)
    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    user_data = fake_users_db.get(username)
    if user_data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    return user_data


def require_role(required_role: str):
    """
    Зависимость для проверки роли пользователя.
    admin >= user >= guest
    """
    def role_checker(user_data: dict = Depends(get_current_user_from_token)):
        user_role = user_data.get("role", "guest")

        # Иерархия ролей: admin имеет все права
        role_hierarchy = {"admin": 3, "user": 2, "guest": 1}

        if role_hierarchy.get(user_role, 0) < role_hierarchy.get(required_role, 0):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user_role}' does not have sufficient permissions. Required: '{required_role}'",
            )
        return user_data

    return role_checker


@app.get("/protected_resource")
async def protected_resource(user: dict = Depends(require_role("user"))):
    """
    Задание 7.1: Защищённый ресурс — доступ для user и admin.
    """
    return {"message": f"Access granted for user: {user['username']}, role: {user['role']}"}


@app.post("/admin_only_resource")
async def admin_resource(user: dict = Depends(require_role("admin"))):
    """
    Задание 7.1: Ресурс только для admin (создание).
    """
    return {"message": f"Admin action performed by: {user['username']}"}


@app.get("/guest_resource")
async def guest_resource(user: dict = Depends(require_role("guest"))):
    """
    Задание 7.1: Ресурс для guest (только чтение).
    """
    return {"message": f"Guest reading data as: {user['username']}"}


# ============================================================
# Задание 8.1: Регистрация через SQLite (raw SQL)
# ============================================================

@app.post("/register_db")
async def register_db(user: User):
    """
    Задание 8.1: Регистрация пользователя через SQLite (raw SQL).
    POST /register_db
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (user.username, user.password),
        )
        conn.commit()
        return {"message": "User registered successfully!"}
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists in database",
        )
    finally:
        conn.close()


# ============================================================
# Задание 8.2: CRUD для Todo (SQLite, raw SQL)
# ============================================================

@app.post("/todos", status_code=status.HTTP_201_CREATED, response_model=TodoResponse)
async def create_todo(todo: TodoCreate):
    """
    Задание 8.2: Создание Todo.
    POST /todos
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO todos (title, description, completed) VALUES (?, ?, ?)",
        (todo.title, todo.description, 0),
    )
    conn.commit()
    todo_id = cursor.lastrowid
    conn.close()

    return TodoResponse(id=todo_id, title=todo.title, description=todo.description, completed=False)


@app.get("/todos/{todo_id}", response_model=TodoResponse)
async def get_todo(todo_id: int):
    """
    Задание 8.2: Получение Todo по ID.
    GET /todos/{todo_id}
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM todos WHERE id = ?", (todo_id,))
    row = cursor.fetchone()
    conn.close()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Todo not found",
        )

    return TodoResponse(
        id=row["id"],
        title=row["title"],
        description=row["description"],
        completed=bool(row["completed"]),
    )


@app.put("/todos/{todo_id}", response_model=TodoResponse)
async def update_todo(todo_id: int, todo: TodoUpdate):
    """
    Задание 8.2: Обновление Todo.
    PUT /todos/{todo_id}
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Проверяем существование
    cursor.execute("SELECT * FROM todos WHERE id = ?", (todo_id,))
    existing = cursor.fetchone()
    if existing is None:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Todo not found",
        )

    # Обновляем только переданные поля
    title = todo.title if todo.title is not None else existing["title"]
    description = todo.description if todo.description is not None else existing["description"]
    completed = int(todo.completed) if todo.completed is not None else existing["completed"]

    cursor.execute(
        "UPDATE todos SET title = ?, description = ?, completed = ? WHERE id = ?",
        (title, description, completed, todo_id),
    )
    conn.commit()

    updated = cursor.execute("SELECT * FROM todos WHERE id = ?", (todo_id,)).fetchone()
    conn.close()

    return TodoResponse(
        id=updated["id"],
        title=updated["title"],
        description=updated["description"],
        completed=bool(updated["completed"]),
    )


@app.delete("/todos/{todo_id}")
async def delete_todo(todo_id: int):
    """
    Задание 8.2: Удаление Todo.
    DELETE /todos/{todo_id}
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
    conn.commit()
    affected = cursor.rowcount
    conn.close()

    if affected == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Todo not found",
        )

    return {"message": "Todo deleted successfully"}


# ============================================================
# Запуск приложения
# ============================================================

@app.on_event("startup")
def on_startup():
    """Инициализация БД при запуске."""
    init_db()
