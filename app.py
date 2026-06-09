"""
Лёгкий мессенджер: регистрация, аватарки, передача файлов, автоочистка.

- База: SQLite локально / PostgreSQL на хостинге (через DATABASE_URL).
- Аватарки хранятся в базе (маленькие, сжатые на стороне браузера).
- Файлы загружаются на сервер ВРЕМЕННО: доходят в любой сети, отправителю
  не нужно держать вкладку открытой. Удаляются автоматически через 24 часа.
- Сообщения старше 7 дней автоматически удаляются.
"""

import os
import uuid
import json
import hashlib
from datetime import datetime, timezone, timedelta

from flask import (
    Flask, request, session, redirect, url_for,
    render_template, jsonify, g, send_file, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-please-12345")

# Сколько хранить сообщения (дней) и файлы (часов)
MESSAGE_TTL_DAYS = 7
FILE_TTL_HOURS = 24

# Максимальный размер загружаемого файла (25 МБ — безопасно для бесплатного хостинга)
MAX_FILE_MB = 25
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_MB * 1024 * 1024

# Папка для временных файлов
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

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
        if USE_POSTGRES:
            get_db().rollback()


def init_db():
    if USE_POSTGRES:
        users_sql = """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                pw_hash TEXT NOT NULL, avatar TEXT)"""
        msgs_sql = """
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY, username TEXT NOT NULL, text TEXT NOT NULL,
                kind TEXT DEFAULT 'text', created TEXT NOT NULL, recipient TEXT)"""
        files_sql = """
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, size INTEGER NOT NULL,
                path TEXT NOT NULL, owner TEXT NOT NULL, created TEXT NOT NULL,
                hash TEXT)"""
    else:
        users_sql = """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
                pw_hash TEXT NOT NULL, avatar TEXT)"""
        msgs_sql = """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL,
                text TEXT NOT NULL, kind TEXT DEFAULT 'text', created TEXT NOT NULL,
                recipient TEXT)"""
        files_sql = """
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, size INTEGER NOT NULL,
                path TEXT NOT NULL, owner TEXT NOT NULL, created TEXT NOT NULL,
                hash TEXT)"""
    db = get_db()
    cur = db.cursor()
    cur.execute(users_sql)
    cur.execute(msgs_sql)
    cur.execute(files_sql)
    # таблица прочтений: до какого id сообщения каждый пользователь дочитал
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reads (
            username TEXT PRIMARY KEY,
            last_read_id INTEGER DEFAULT 0
        )""")
    # реакции эмодзи: одна строка = (сообщение, пользователь, эмодзи)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reactions (
            message_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            emoji TEXT NOT NULL
        )""")
    db.commit()
    cur.close()
    safe_alter("ALTER TABLE users ADD COLUMN avatar TEXT")
    safe_alter("ALTER TABLE messages ADD COLUMN kind TEXT DEFAULT 'text'")
    safe_alter("ALTER TABLE users ADD COLUMN last_seen TEXT")
    safe_alter("ALTER TABLE messages ADD COLUMN recipient TEXT")
    safe_alter("ALTER TABLE messages ADD COLUMN reply_to INTEGER")
    safe_alter("ALTER TABLE messages ADD COLUMN attachments TEXT")
    safe_alter("ALTER TABLE files ADD COLUMN hash TEXT")
    safe_alter("ALTER TABLE messages ADD COLUMN edited INTEGER DEFAULT 0")
    safe_alter("ALTER TABLE messages ADD COLUMN deleted INTEGER DEFAULT 0")


def cleanup_old():
    """Удаляет старые сообщения и файлы."""
    # Сообщения старше N дней
    cutoff = (datetime.now(timezone.utc) - timedelta(days=MESSAGE_TTL_DAYS)).isoformat()
    query(f"DELETE FROM messages WHERE created < {PLACEHOLDER}", (cutoff,), commit=True)

    # Файлы старше N часов: сначала удаляем сами файлы с диска, потом записи
    fcut = (datetime.now(timezone.utc) - timedelta(hours=FILE_TTL_HOURS)).isoformat()
    old = query(
        f"SELECT id, path FROM files WHERE created < {PLACEHOLDER}", (fcut,), fetch=True
    )
    for f in (old or []):
        try:
            if os.path.exists(f["path"]):
                os.remove(f["path"])
        except Exception:
            pass
    if old:
        query(f"DELETE FROM files WHERE created < {PLACEHOLDER}", (fcut,), commit=True)
    # заодно убираем дубликаты файлов
    dedup_files()


def _hash_file(path):
    """SHA-256 содержимого файла."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fp:
            for chunk in iter(lambda: fp.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def dedup_files():
    """Удаляет дубликаты файлов (одинаковый hash), оставляя самый новый.
    Чистит и записи в БД, и сами файлы на диске."""
    rows = query(
        "SELECT id, path, hash, created FROM files WHERE hash IS NOT NULL "
        "ORDER BY created DESC", fetch=True,
    )
    seen = set()
    to_delete = []
    for r in (rows or []):
        h = r["hash"]
        if h in seen:
            to_delete.append(r)          # это более старый дубликат
        else:
            seen.add(h)                  # самый новый — оставляем
    for r in to_delete:
        try:
            if r["path"] and os.path.exists(r["path"]):
                os.remove(r["path"])
        except Exception:
            pass
        query(f"DELETE FROM files WHERE id = {PLACEHOLDER}", (r["id"],), commit=True)


# -----------------------------------------------------------------------------
# Страницы
# -----------------------------------------------------------------------------
@app.route("/")
def index():
    if "user" not in session:
        return redirect(url_for("login"))
    touch_presence()
    return render_template("chat.html", user=session["user"], max_mb=MAX_FILE_MB)


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
                    f"INSERT INTO users (username, pw_hash) VALUES ({PLACEHOLDER}, {PLACEHOLDER})",
                    (username, generate_password_hash(password)), commit=True,
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
# Присутствие (онлайн-статус)
# -----------------------------------------------------------------------------
# Пользователь считается онлайн, если был активен в последние ONLINE_WINDOW сек
ONLINE_WINDOW = 35


def touch_presence():
    """Обновляет время последней активности текущего пользователя."""
    if "user" in session:
        query(
            f"UPDATE users SET last_seen = {PLACEHOLDER} WHERE username = {PLACEHOLDER}",
            (datetime.now(timezone.utc).isoformat(), session["user"]),
            commit=True,
        )


@app.route("/api/heartbeat", methods=["POST"])
def heartbeat():
    """Лёгкий пинг: подтверждает, что пользователь онлайн."""
    if "user" not in session:
        return jsonify({"error": "auth"}), 401
    touch_presence()
    return jsonify({"ok": True})


# Кто сейчас печатает: username -> время последнего сигнала
TYPING = {}


@app.route("/api/typing", methods=["POST"])
def set_typing():
    """Пользователь сообщает, что печатает."""
    if "user" not in session:
        return jsonify({"error": "auth"}), 401
    TYPING[session["user"]] = datetime.now(timezone.utc)
    return jsonify({"ok": True})


@app.route("/api/typing")
def get_typing():
    """Кто печатает прямо сейчас (был сигнал в последние 4 сек), кроме меня."""
    if "user" not in session:
        return jsonify({"error": "auth"}), 401
    now = datetime.now(timezone.utc)
    active = [
        u for u, t in TYPING.items()
        if u != session["user"] and (now - t).total_seconds() <= 4
    ]
    return jsonify(active)


def is_online(last_seen):
    if not last_seen:
        return False
    try:
        seen = datetime.fromisoformat(last_seen)
        return (datetime.now(timezone.utc) - seen).total_seconds() <= ONLINE_WINDOW
    except Exception:
        return False


@app.route("/api/presence")
def get_presence():
    """Возвращает словарь {username: True/False} — кто сейчас онлайн."""
    if "user" not in session:
        return jsonify({"error": "auth"}), 401
    touch_presence()
    rows = query("SELECT username, last_seen FROM users", fetch=True)
    return jsonify({r["username"]: is_online(r.get("last_seen")) for r in rows})


@app.route("/api/users")
def get_users():
    """Все участники с аватаркой и онлайн-статусом (для панели участников)."""
    if "user" not in session:
        return jsonify({"error": "auth"}), 401
    touch_presence()
    rows = query("SELECT username, avatar, last_seen FROM users ORDER BY username", fetch=True)
    return jsonify([
        {"username": r["username"], "avatar": r.get("avatar"),
         "online": is_online(r.get("last_seen"))}
        for r in rows
    ])


# -----------------------------------------------------------------------------
# Прочтение сообщений
# -----------------------------------------------------------------------------
@app.route("/api/read", methods=["POST"])
def mark_read():
    """Отмечает, что текущий пользователь прочитал сообщения до last_id."""
    if "user" not in session:
        return jsonify({"error": "auth"}), 401
    last_id = (request.json or {}).get("last_id", 0)
    try:
        last_id = int(last_id)
    except Exception:
        last_id = 0
    me = session["user"]
    # upsert: создаём запись или обновляем, не уменьшая значение
    existing = query(
        f"SELECT last_read_id FROM reads WHERE username = {PLACEHOLDER}",
        (me,), fetch=True,
    )
    if existing:
        cur_val = existing[0]["last_read_id"] or 0
        if last_id > cur_val:
            query(
                f"UPDATE reads SET last_read_id = {PLACEHOLDER} WHERE username = {PLACEHOLDER}",
                (last_id, me), commit=True,
            )
    else:
        query(
            f"INSERT INTO reads (username, last_read_id) VALUES ({PLACEHOLDER}, {PLACEHOLDER})",
            (me, last_id), commit=True,
        )
    return jsonify({"ok": True})


@app.route("/api/reads")
def get_reads():
    """Возвращает {username: last_read_id} — кто до какого сообщения дочитал."""
    if "user" not in session:
        return jsonify({"error": "auth"}), 401
    rows = query("SELECT username, last_read_id FROM reads", fetch=True)
    return jsonify({r["username"]: (r["last_read_id"] or 0) for r in rows})


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
    if len(avatar) > 300_000:
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
    touch_presence()
    cleanup_old()
    after = request.args.get("after", 0, type=int)
    me = session["user"]
    # Показываем: общие сообщения (recipient IS NULL) + личные, где я отправитель
    # или получатель. Чужие личные не отдаём.
    rows = query(
        f"SELECT id, username, text, kind, created, recipient, reply_to, attachments, edited, deleted "
        f"FROM messages "
        f"WHERE id > {PLACEHOLDER} AND ("
        f"  recipient IS NULL"
        f"  OR username = {PLACEHOLDER}"
        f"  OR recipient = {PLACEHOLDER}"
        f") ORDER BY id ASC LIMIT 200",
        (after, me, me), fetch=True,
    )
    # парсим attachments из JSON-строки в список
    for r in rows:
        if r.get("attachments"):
            try:
                r["attachments"] = json.loads(r["attachments"])
            except Exception:
                r["attachments"] = []
        else:
            r["attachments"] = []
    return jsonify(rows)


@app.route("/api/reactions")
def get_reactions():
    """Все реакции: {message_id: {emoji: [usernames]}}."""
    if "user" not in session:
        return jsonify({"error": "auth"}), 401
    rows = query("SELECT message_id, username, emoji FROM reactions", fetch=True)
    result = {}
    for r in rows:
        mid = str(r["message_id"])
        result.setdefault(mid, {}).setdefault(r["emoji"], []).append(r["username"])
    return jsonify(result)


@app.route("/api/react", methods=["POST"])
def react():
    """Поставить/снять реакцию (тоггл) на сообщение."""
    if "user" not in session:
        return jsonify({"error": "auth"}), 401
    data = request.json or {}
    try:
        mid = int(data.get("message_id"))
    except Exception:
        return jsonify({"error": "bad"}), 400
    emoji = (data.get("emoji") or "")[:8]
    if not emoji:
        return jsonify({"error": "bad"}), 400
    me = session["user"]
    existing = query(
        f"SELECT 1 FROM reactions WHERE message_id = {PLACEHOLDER} "
        f"AND username = {PLACEHOLDER} AND emoji = {PLACEHOLDER}",
        (mid, me, emoji), fetch=True,
    )
    if existing:
        query(
            f"DELETE FROM reactions WHERE message_id = {PLACEHOLDER} "
            f"AND username = {PLACEHOLDER} AND emoji = {PLACEHOLDER}",
            (mid, me, emoji), commit=True,
        )
    else:
        query(
            f"INSERT INTO reactions (message_id, username, emoji) "
            f"VALUES ({PLACEHOLDER}, {PLACEHOLDER}, {PLACEHOLDER})",
            (mid, me, emoji), commit=True,
        )
    return jsonify({"ok": True})


@app.route("/api/send", methods=["POST"])
def send_message():
    if "user" not in session:
        return jsonify({"error": "auth"}), 401
    data = request.json or {}
    text = (data.get("text", "") or "").strip()
    kind = "text"
    reply_to = data.get("reply_to")
    try:
        reply_to = int(reply_to) if reply_to else None
    except Exception:
        reply_to = None

    # вложения: список fileId, которые юзер прикрепил
    attach_ids = data.get("attachments") or []
    attachments = []
    if isinstance(attach_ids, list) and attach_ids:
        for fid in attach_ids[:10]:
            rows = query(
                f"SELECT id, name, size FROM files WHERE id = {PLACEHOLDER}",
                (str(fid),), fetch=True,
            )
            if rows:
                r = rows[0]
                ext = os.path.splitext(r["name"])[1].lower()
                is_image = ext in (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp")
                attachments.append({
                    "fileId": r["id"], "name": r["name"],
                    "size": r["size"], "isImage": is_image,
                })

    # пустое сообщение без вложений — не отправляем
    if not text and not attachments:
        return jsonify({"error": "empty"}), 400
    text = text[:4000]

    recipient = None
    # Личное сообщение через команду:  /w имя текст
    if text.startswith("/w "):
        rest = text[3:].lstrip()
        parts = rest.split(None, 1)
        if len(parts) < 2 or not parts[1].strip():
            return jsonify({"error": "Используйте: /w <имя> сообщение"}), 400
        target = parts[0].strip().lstrip("@").lower()
        body = parts[1].strip()
        exists = query(
            f"SELECT username FROM users WHERE username = {PLACEHOLDER}",
            (target,), fetch=True,
        )
        if not exists:
            return jsonify({"error": f"Пользователь @{target} не найден"}), 400
        if target == session["user"]:
            return jsonify({"error": "Нельзя писать личное самому себе"}), 400
        recipient = exists[0]["username"]
        text = body[:4000]

    att_json = json.dumps(attachments) if attachments else None
    query(
        f"INSERT INTO messages (username, text, kind, created, recipient, reply_to, attachments) "
        f"VALUES ({PLACEHOLDER}, {PLACEHOLDER}, {PLACEHOLDER}, {PLACEHOLDER}, {PLACEHOLDER}, {PLACEHOLDER}, {PLACEHOLDER})",
        (session["user"], text, kind, datetime.now(timezone.utc).isoformat(),
         recipient, reply_to, att_json),
        commit=True,
    )
    return jsonify({"ok": True, "private": recipient is not None})


@app.route("/api/edit", methods=["POST"])
def edit_message():
    """Редактирование своего текстового сообщения."""
    if "user" not in session:
        return jsonify({"error": "auth"}), 401
    data = request.json or {}
    try:
        mid = int(data.get("id"))
    except Exception:
        return jsonify({"error": "bad"}), 400
    new_text = (data.get("text", "") or "").strip()[:4000]
    if not new_text:
        return jsonify({"error": "Текст не может быть пустым"}), 400
    rows = query(
        f"SELECT username, deleted FROM messages WHERE id = {PLACEHOLDER}",
        (mid,), fetch=True,
    )
    if not rows:
        return jsonify({"error": "not_found"}), 404
    if rows[0]["username"] != session["user"]:
        return jsonify({"error": "Можно редактировать только свои сообщения"}), 403
    if rows[0].get("deleted"):
        return jsonify({"error": "Сообщение удалено"}), 400
    query(
        f"UPDATE messages SET text = {PLACEHOLDER}, edited = 1 WHERE id = {PLACEHOLDER}",
        (new_text, mid), commit=True,
    )
    return jsonify({"ok": True})


@app.route("/api/delete", methods=["POST"])
def delete_message():
    """Полное удаление своего сообщения (строка стирается из БД)."""
    if "user" not in session:
        return jsonify({"error": "auth"}), 401
    data = request.json or {}
    try:
        mid = int(data.get("id"))
    except Exception:
        return jsonify({"error": "bad"}), 400
    rows = query(
        f"SELECT username FROM messages WHERE id = {PLACEHOLDER}",
        (mid,), fetch=True,
    )
    if not rows:
        return jsonify({"error": "not_found"}), 404
    if rows[0]["username"] != session["user"]:
        return jsonify({"error": "Можно удалять только свои сообщения"}), 403
    # полностью удаляем сообщение и его реакции
    query(f"DELETE FROM messages WHERE id = {PLACEHOLDER}", (mid,), commit=True)
    query(f"DELETE FROM reactions WHERE message_id = {PLACEHOLDER}", (mid,), commit=True)
    return jsonify({"ok": True})


@app.route("/api/changes")
def get_changes():
    """Состояние ранее показанных сообщений (для синхронизации правок и
    удалений). Принимает ids=1,2,3 — возвращает существующие (с text/edited)
    и список missing — id, которых уже нет (удалены)."""
    if "user" not in session:
        return jsonify({"error": "auth"}), 401
    ids_param = request.args.get("ids", "")
    try:
        ids = [int(x) for x in ids_param.split(",") if x.strip()][:300]
    except Exception:
        ids = []
    if not ids:
        return jsonify({"items": [], "missing": []})
    placeholders = ",".join([PLACEHOLDER] * len(ids))
    rows = query(
        f"SELECT id, text, edited FROM messages WHERE id IN ({placeholders})",
        tuple(ids), fetch=True,
    )
    present = {r["id"] for r in rows}
    missing = [i for i in ids if i not in present]
    return jsonify({"items": rows, "missing": missing})


# -----------------------------------------------------------------------------
# Файлы: временное хранение на сервере с авто-удалением
# -----------------------------------------------------------------------------
@app.route("/api/upload", methods=["POST"])
def upload_file():
    if "user" not in session:
        return jsonify({"error": "auth"}), 401
    if "file" not in request.files:
        return jsonify({"error": "no_file"}), 400
    f = request.files["file"]
    if not f or not f.filename:
        return jsonify({"error": "no_file"}), 400

    file_id = uuid.uuid4().hex
    orig_name = f.filename
    # имя на диске безопасное и уникальное
    disk_name = file_id + "_" + (secure_filename(orig_name) or "file")
    path = os.path.join(UPLOAD_DIR, disk_name)
    f.save(path)
    size = os.path.getsize(path)

    # хеш содержимого для дедупликации
    file_hash = _hash_file(path)

    # является ли файл картинкой (для превью)
    ext = os.path.splitext(orig_name)[1].lower()
    is_image = ext in (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp")

    query(
        f"INSERT INTO files (id, name, size, path, owner, created, hash) "
        f"VALUES ({PLACEHOLDER}, {PLACEHOLDER}, {PLACEHOLDER}, {PLACEHOLDER}, {PLACEHOLDER}, {PLACEHOLDER}, {PLACEHOLDER})",
        (file_id, orig_name, size, path, session["user"],
         datetime.now(timezone.utc).isoformat(), file_hash),
        commit=True,
    )

    # удаляем старые дубликаты этого же содержимого (оставляем самый новый)
    dedup_files()

    # Возвращаем метаданные — сообщение создаст /api/send как вложение
    return jsonify({
        "ok": True,
        "fileId": file_id, "name": orig_name, "size": size, "isImage": is_image,
    })


@app.route("/api/file/<file_id>")
def download_file(file_id):
    if "user" not in session:
        return abort(401)
    rows = query(
        f"SELECT name, path FROM files WHERE id = {PLACEHOLDER}", (file_id,), fetch=True
    )
    if not rows:
        return abort(404)
    info = rows[0]
    if not os.path.exists(info["path"]):
        return abort(404)
    return send_file(info["path"], as_attachment=True, download_name=info["name"])


@app.route("/api/image/<file_id>")
def view_image(file_id):
    """Отдаёт картинку для показа прямо в чате (не как вложение)."""
    if "user" not in session:
        return abort(401)
    rows = query(
        f"SELECT name, path FROM files WHERE id = {PLACEHOLDER}", (file_id,), fetch=True
    )
    if not rows:
        return abort(404)
    info = rows[0]
    if not os.path.exists(info["path"]):
        return abort(404)
    return send_file(info["path"], download_name=info["name"])


with app.app_context():
    init_db()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
