"""
Лёгкий мессенджер для небольшой группы людей.
Один общий чат, вход по имени и паролю, сообщения хранятся в SQLite.
Работает в браузере (компьютер + телефон).
"""

import os
import sqlite3
from datetime import datetime, timezone

from flask import (
    Flask, request, session, redirect, url_for,
    render_template, jsonify, g
)

app = Flask(__name__)
# Секретный ключ для сессий (на хостинге задаётся через переменную окружения)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-please-12345")

DB_PATH = os.environ.get("DB_PATH", "chat.db")

# -----------------------------------------------------------------------------
# Пользователи. Логин: пароль. Поменяй на свои.
# Достаточно для трёх человек.
# -----------------------------------------------------------------------------
USERS = {
    "anna":  "anna123",
    "boris": "boris123",
    "vera":  "vera123",
}


# -----------------------------------------------------------------------------
# Работа с базой данных
# -----------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT NOT NULL,
            text      TEXT NOT NULL,
            created   TEXT NOT NULL
        )
        """
    )
    db.commit()
    db.close()


# -----------------------------------------------------------------------------
# Маршруты
# -----------------------------------------------------------------------------
@app.route("/")
def index():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("chat.html", user=session["user"])


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        if USERS.get(username) == password:
            session["user"] = username
            return redirect(url_for("index"))
        error = "Неверное имя или пароль"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


@app.route("/api/messages")
def get_messages():
    if "user" not in session:
        return jsonify({"error": "auth"}), 401
    # Отдаём сообщения после переданного id (для подгрузки новых)
    after = request.args.get("after", 0, type=int)
    rows = get_db().execute(
        "SELECT id, username, text, created FROM messages "
        "WHERE id > ? ORDER BY id ASC LIMIT 200",
        (after,),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/send", methods=["POST"])
def send_message():
    if "user" not in session:
        return jsonify({"error": "auth"}), 401
    text = (request.json or {}).get("text", "").strip()
    if not text:
        return jsonify({"error": "empty"}), 400
    if len(text) > 2000:
        text = text[:2000]
    db = get_db()
    db.execute(
        "INSERT INTO messages (username, text, created) VALUES (?, ?, ?)",
        (session["user"], text, datetime.now(timezone.utc).isoformat()),
    )
    db.commit()
    return jsonify({"ok": True})


# Инициализируем БД при импорте (важно для gunicorn на хостинге)
init_db()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
