"""
Лёгкий мессенджер: регистрация, аватарки, P2P-передача файлов, автоочистка.

- База: SQLite локально / PostgreSQL на хостинге (через DATABASE_URL).
- Аватарки хранятся в базе (маленькие, сжатые на стороне браузера).
- Файлы НЕ хранятся на сервере: они передаются напрямую между браузерами
  по WebRTC. Сервер используется только как "посредник" для установления
  соединения (обмен сигналами). Отправитель должен быть онлайн.
- Сообщения старше 7 дней автоматически удаляются.
"""

import os
from datetime import datetime, timezone, timedelta

from flask import (
    Flask, request, session, redirect, url_for,
    render_template, jsonify, g
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-please-12345")

# Сколько хранить сообщения (дней)
MESSAGE_TTL_DAYS = 7

# -----------------------------------------------------------------------------
# Выбор базы данных
# -----------------------------------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL", "")
USE_POSTGRES = DATABASE_URL.startswith("postgres")

if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    PLACEHOLDER = "%s"
else:
    import sqlite3
    DB_PATH = os.environ.get("DB_PATH", "chat.db")
    PLACEHOLDER = "?"


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
    return [dict(r) for r in rows]


def safe_alter(sql):
    """Добавление колонки в существующую БД (если её ещё нет)."""
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute(sql)
        db.commit()
        cur.close()
    except Exception:
        # колонка уже есть — это нормально
        get_db().rollback() if USE_POSTGRES else None


def init_db():
    if USE_POSTGRES:
        users_sql = """
            CREATE TABLE IF NOT EXISTS users (
                id       SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                pw_hash  TEXT NOT NULL,
                avatar   TEXT
            )"""
        msgs_sql = """
            CREATE TABLE IF NOT EXISTS messages (
                id       SERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                text     TEXT NOT NULL,
                kind     TEXT DEFAULT 'text',
                created  TEXT NOT NULL
            )"""
        signals_sql = """
            CREATE TABLE IF NOT EXISTS signals (
                id       SERIAL PRIMARY KEY,
                target   TEXT NOT NULL,
                sender   TEXT NOT NULL,
                data     TEXT NOT NULL,
                created  TEXT NOT NULL
            )"""
    else:
        users_sql = """
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                pw_hash  TEXT NOT NULL,
                avatar   TEXT
            )"""
        msgs_sql = """
            CREATE TABLE IF NOT EXISTS messages (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                text     TEXT NOT NULL,
                kind     TEXT DEFAULT 'text',
                created  TEXT NOT NULL
            )"""
        signals_sql = """
            CREATE TABLE IF NOT EXISTS signals (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                target   TEXT NOT NULL,
                sender   TEXT NOT NULL,
                data     TEXT NOT NULL,
                created  TEXT NOT NULL
            )"""
    db = get_db()
    cur = db.cursor()
    cur.execute(users_sql)
    cur.execute(msgs_sql)
    cur.execute(signals_sql)
    db.commit()
    cur.close()
    # Миграции для старых баз
    safe_alter("ALTER TABLE users ADD COLUMN avatar TEXT")
    safe_alter("ALTER TABLE messages ADD COLUMN kind TEXT DEFAULT 'text'")


def cleanup_old():
    """Удаляет сообщения старше MESSAGE_TTL_DAYS и старые сигналы."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=MESSAGE_TTL_DAYS)).isoformat()
    query(f"DELETE FROM messages WHERE created < {PLACEHOLDER}", (cutoff,), commit=True)
    # сигналы живут секунды — чистим всё старше 1 минуты, чтобы не копились
    sig_cutoff = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    query(f"DELETE FROM signals WHERE created < {PLACEHOLDER}", (sig_cutoff,), commit=True)


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
# Аватарки
# -----------------------------------------------------------------------------
@app.route("/api/avatar", methods=["POST"])
def set_avatar():
    if "user" not in session:
        return jsonify({"error": "auth"}), 401
    avatar = (request.json or {}).get("avatar", "")
    if not avatar.startswith("data:image/"):
        return jsonify({"error": "bad"}), 400
    if len(avatar) > 300_000:  # ~300 КБ максимум
        return jsonify({"error": "too_big"}), 400
    query(
        f"UPDATE users SET avatar = {PLACEHOLDER} WHERE username = {PLACEHOLDER}",
        (avatar, session["user"]), commit=True,
    )
    return jsonify({"ok": True})


@app.route("/api/avatars")
def get_avatars():
    if "user" not in session:
        return jsonify({"error": "auth"}), 401
    rows = query("SELECT username, avatar FROM users", fetch=True)
    return jsonify({r["username"]: r["avatar"] for r in rows if r["avatar"]})


# -----------------------------------------------------------------------------
# Сообщения
# -----------------------------------------------------------------------------
@app.route("/api/messages")
def get_messages():
    if "user" not in session:
        return jsonify({"error": "auth"}), 401
    cleanup_old()
    after = request.args.get("after", 0, type=int)
    rows = query(
        f"SELECT id, username, text, kind, created FROM messages "
        f"WHERE id > {PLACEHOLDER} ORDER BY id ASC LIMIT 200",
        (after,), fetch=True,
    )
    return jsonify(rows)


@app.route("/api/send", methods=["POST"])
def send_message():
    if "user" not in session:
        return jsonify({"error": "auth"}), 401
    data = request.json or {}
    text = (data.get("text", "") or "").strip()
    kind = data.get("kind", "text")
    if kind not in ("text", "file"):
        kind = "text"
    if not text:
        return jsonify({"error": "empty"}), 400
    text = text[:4000]
    query(
        f"INSERT INTO messages (username, text, kind, created) "
        f"VALUES ({PLACEHOLDER}, {PLACEHOLDER}, {PLACEHOLDER}, {PLACEHOLDER})",
        (session["user"], text, kind, datetime.now(timezone.utc).isoformat()),
        commit=True,
    )
    return jsonify({"ok": True})


# -----------------------------------------------------------------------------
# WebRTC сигналинг (обмен техническими данными для P2P-соединения)
# Сами файлы тут НЕ передаются — только координаты для прямого соединения.
# -----------------------------------------------------------------------------
@app.route("/api/signal", methods=["POST"])
def post_signal():
    if "user" not in session:
        return jsonify({"error": "auth"}), 401
    body = request.json or {}
    target = body.get("to", "")
    data = body.get("data", "")
    if not target or not data:
        return jsonify({"error": "bad"}), 400
    query(
        f"INSERT INTO signals (target, sender, data, created) "
        f"VALUES ({PLACEHOLDER}, {PLACEHOLDER}, {PLACEHOLDER}, {PLACEHOLDER})",
        (target, session["user"], data, datetime.now(timezone.utc).isoformat()),
        commit=True,
    )
    return jsonify({"ok": True})


@app.route("/api/signals")
def get_signals():
    if "user" not in session:
        return jsonify({"error": "auth"}), 401
    me = session["user"]
    rows = query(
        f"SELECT id, sender, data FROM signals WHERE target = {PLACEHOLDER} "
        f"ORDER BY id ASC",
        (me,), fetch=True,
    )
    if rows:
        max_id = max(r["id"] for r in rows)
        query(
            f"DELETE FROM signals WHERE target = {PLACEHOLDER} AND id <= {PLACEHOLDER}",
            (me, max_id), commit=True,
        )
    return jsonify([{"sender": r["sender"], "data": r["data"]} for r in rows])


with app.app_context():
    init_db()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
