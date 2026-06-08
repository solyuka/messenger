"""
Лёгкий мессенджер с регистрацией и постоянным хранением сообщений.

- Локально использует SQLite (файл chat.db) — ничего настраивать не нужно.
- На хостинге, если задана переменная окружения DATABASE_URL (PostgreSQL),
  автоматически использует её — данные сохраняются навсегда.
- Пароли хранятся в зашифрованном виде (хэш).
"""

import os
from datetime import datetime, timezone

from flask import (
    Flask, request, session, redirect, url_for,
    render_template, jsonify, g
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-please-12345")

# -----------------------------------------------------------------------------
# Выбор базы данных:
#   - есть DATABASE_URL  -> PostgreSQL (постоянное хранилище на хостинге)
#   - нет                -> SQLite (локально, файл chat.db)
# -----------------------------------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL", "")
USE_POSTGRES = DATABASE_URL.startswith("postgres")

if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras
    # Render иногда выдаёт URL вида postgres://, psycopg2 ждёт postgresql://
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    PLACEHOLDER = "%s"   # стиль подстановки параметров в PostgreSQL
else:
    import sqlite3
    DB_PATH = os.environ.get("DB_PATH", "chat.db")
    PLACEHOLDER = "?"    # стиль подстановки параметров в SQLite


# -----------------------------------------------------------------------------
# Подключение к БД
# -----------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        if USE_POSTGRES:
            g.db = psycopg2.connect(DATABASE_URL)
        else:
            g.db = sqlite3.connect(DB_PATH)
            g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query(sql, params=(), fetch=False, commit=False):
    """Универсальный помощник для SQLite и PostgreSQL."""
    db = get_db()
    if USE_POSTGRES:
        cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    else:
        cur = db.cursor()
    cur.execute(sql, params)
    rows = cur.fetchall() if fetch else None
    if commit:
        db.commit()
    cur.close()
    if rows is None:
        return None
    # Приводим к списку обычных словарей
    if USE_POSTGRES:
        return [dict(r) for r in rows]
    return [dict(r) for r in rows]


def init_db():
    if USE_POSTGRES:
        users_sql = """
            CREATE TABLE IF NOT EXISTS users (
                id       SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                pw_hash  TEXT NOT NULL
            )"""
        msgs_sql = """
            CREATE TABLE IF NOT EXISTS messages (
                id       SERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                text     TEXT NOT NULL,
                created  TEXT NOT NULL
            )"""
    else:
        users_sql = """
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                pw_hash  TEXT NOT NULL
            )"""
        msgs_sql = """
            CREATE TABLE IF NOT EXISTS messages (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                text     TEXT NOT NULL,
                created  TEXT NOT NULL
            )"""
    db = get_db()
    cur = db.cursor()
    cur.execute(users_sql)
    cur.execute(msgs_sql)
    db.commit()
    cur.close()


# -----------------------------------------------------------------------------
# Страницы
# -----------------------------------------------------------------------------
@app.route("/")
def index():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("chat.html", user=session["user"])


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")

        if not username or not password:
            error = "Заполните имя и пароль"
        elif len(username) < 3:
            error = "Имя должно быть не короче 3 символов"
        elif len(password) < 4:
            error = "Пароль должен быть не короче 4 символов"
        elif password != password2:
            error = "Пароли не совпадают"
        else:
            exists = query(
                f"SELECT id FROM users WHERE username = {PLACEHOLDER}",
                (username,), fetch=True,
            )
            if exists:
                error = "Такое имя уже занято"
            else:
                query(
                    f"INSERT INTO users (username, pw_hash) "
                    f"VALUES ({PLACEHOLDER}, {PLACEHOLDER})",
                    (username, generate_password_hash(password)),
                    commit=True,
                )
                session["user"] = username
                return redirect(url_for("index"))

    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        rows = query(
            f"SELECT pw_hash FROM users WHERE username = {PLACEHOLDER}",
            (username,), fetch=True,
        )
        if rows and check_password_hash(rows[0]["pw_hash"], password):
            session["user"] = username
            return redirect(url_for("index"))
        error = "Неверное имя или пароль"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


# -----------------------------------------------------------------------------
# API
# -----------------------------------------------------------------------------
@app.route("/api/messages")
def get_messages():
    if "user" not in session:
        return jsonify({"error": "auth"}), 401
    after = request.args.get("after", 0, type=int)
    rows = query(
        f"SELECT id, username, text, created FROM messages "
        f"WHERE id > {PLACEHOLDER} ORDER BY id ASC LIMIT 200",
        (after,), fetch=True,
    )
    return jsonify(rows)


@app.route("/api/send", methods=["POST"])
def send_message():
    if "user" not in session:
        return jsonify({"error": "auth"}), 401
    text = (request.json or {}).get("text", "").strip()
    if not text:
        return jsonify({"error": "empty"}), 400
    text = text[:2000]
    query(
        f"INSERT INTO messages (username, text, created) "
        f"VALUES ({PLACEHOLDER}, {PLACEHOLDER}, {PLACEHOLDER})",
        (session["user"], text, datetime.now(timezone.utc).isoformat()),
        commit=True,
    )
    return jsonify({"ok": True})


# Создаём таблицы при старте (нужно для gunicorn на хостинге)
with app.app_context():
    init_db()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
