import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")


def get_db_connection():
    """Подключение к SQLite базе данных."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Инициализация базы данных — создание таблиц users и todos."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Таблица users (Задание 8.1)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)

    # Таблица todos (Задание 8.2)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            completed INTEGER DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()
