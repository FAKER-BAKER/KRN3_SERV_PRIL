from pydantic import BaseModel
from typing import Optional


# --- Задание 6.2: Модели для аутентификации ---

class UserBase(BaseModel):
    username: str


class User(UserBase):
    password: str


class UserInDB(UserBase):
    hashed_password: str


# --- Задание 6.4/6.5: Модель для JWT логина ---

class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# --- Задание 7.1: Модель пользователя с ролью ---

class UserWithRole(UserBase):
    password: str
    role: str = "guest"  # admin, user, guest


class UserInDBWithRole(UserBase):
    hashed_password: str
    role: str = "guest"


# --- Задание 8.2: Модели для Todo ---

class TodoCreate(BaseModel):
    title: str
    description: str


class TodoUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    completed: Optional[bool] = None


class TodoResponse(BaseModel):
    id: int
    title: str
    description: str
    completed: bool

    class Config:
        from_attributes = True
