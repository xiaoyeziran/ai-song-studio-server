# -*- coding: utf-8 -*-
"""
AI 歌曲工坊 - 后端服务
提供:用户注册 / 登录 / 账号状态校验 / 管理员后台(启用·禁用账号)
数据库:自动适配 —— 设置 DATABASE_URL 时使用 PostgreSQL(Replit 等云平台),否则使用 SQLite(本地/EXE 测试)
运行: uvicorn main:app --host 0.0.0.0 --port 8000   (或 python main.py, 自动读 PORT 环境变量)
"""
import os
import hmac
import hashlib
import base64
import json
import secrets
import time
from datetime import datetime, timezone

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "server.db"))
DATABASE_URL = os.environ.get("DATABASE_URL", "")
PG = bool(DATABASE_URL)

if PG:
    import psycopg2
    import psycopg2.extras
else:
    import sqlite3

SECRET_FILE = os.path.join(BASE_DIR, "server_secret.key")
# 新注册用户默认是否可直接使用: 1=注册即用, 0=需管理员在后台开启
NEW_USER_ACTIVE = os.environ.get("NEW_USER_ACTIVE", "1") == "1"
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
TOKEN_TTL = 7 * 24 * 3600  # 7天

app = FastAPI(title="AI 歌曲工坊后端")


def _load_secret() -> bytes:
    # 优先使用环境变量(云平台重启后仍有效), 否则回退到本地文件(仅本地/SQLite 模式)
    env = os.environ.get("APP_SECRET", "")
    if env:
        return env.encode("utf-8")
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "rb") as f:
            return f.read().strip()
    secret = secrets.token_bytes(32)
    try:
        with open(SECRET_FILE, "wb") as f:
            f.write(secret)
    except Exception:
        pass
    return secret


SECRET = _load_secret()


def _conn():
    if PG:
        return psycopg2.connect(DATABASE_URL)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _cur(conn):
    if PG:
        return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    return conn.cursor()


def _q(sql: str) -> str:
    """PostgreSQL 使用 %s 占位符, SQLite 使用 ? """
    return sql.replace("?", "%s") if PG else sql


def _hash_password(password: str, salt: bytes) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return base64.b64encode(digest).decode("ascii")


def _make_token(payload: dict) -> str:
    body = base64.urlsafe_b64encode(json.dumps(payload, ensure_ascii=False).encode("utf-8")).decode("ascii").rstrip("=")
    sig = hmac.new(SECRET, body.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def _verify_token(token: str):
    try:
        body, sig = token.split(".")
        expect = hmac.new(SECRET, body.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, sig):
            return None
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


def _init_db():
    conn = _conn()
    cur = _cur(conn)
    if PG:
        cur.execute(_q("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
        """))
        cur.execute(_q("""
            CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                username TEXT NOT NULL,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL
            )
        """))
    else:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                username TEXT NOT NULL,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)
    cur.execute(_q("SELECT id FROM admin WHERE id = 1"))
    if cur.fetchone() is None:
        salt = secrets.token_bytes(16)
        cur.execute(
            _q("INSERT INTO admin (id, username, salt, password_hash) VALUES (1, ?, ?, ?)"),
            (ADMIN_USERNAME, base64.b64encode(salt).decode("ascii"),
             _hash_password(ADMIN_PASSWORD, salt)),
        )
    conn.commit()
    conn.close()


_init_db()


def _get_admin_row():
    conn = _conn()
    cur = _cur(conn)
    row = cur.execute(_q("SELECT * FROM admin WHERE id = 1")).fetchone()
    conn.close()
    return row


class RegisterBody(BaseModel):
    username: str
    password: str


class LoginBody(BaseModel):
    username: str
    password: str


class StatusBody(BaseModel):
    active: bool


def _check_username(username: str):
    if not username or not username.strip():
        raise HTTPException(400, "用户名不能为空")
    if len(username) < 2 or len(username) > 20:
        raise HTTPException(400, "用户名长度需在 2-20 之间")
    if not all(ch.isalnum() or ch in "_-" for ch in username):
        raise HTTPException(400, "用户名只能包含字母、数字、下划线、中划线")


def _check_password(password: str):
    if not password or len(password) < 6:
        raise HTTPException(400, "密码长度至少 6 位")


@app.post("/api/register")
def register(body: RegisterBody):
    _check_username(body.username)
    _check_password(body.password)
    username = body.username.strip()
    conn = _conn()
    cur = _cur(conn)
    try:
        salt = secrets.token_bytes(16)
        cur.execute(
            _q("INSERT INTO users (username, salt, password_hash, active, created_at) VALUES (?, ?, ?, ?, ?)"),
            (username, base64.b64encode(salt).decode("ascii"),
             _hash_password(body.password, salt),
             1 if NEW_USER_ACTIVE else 0,
             datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        conn.close()
        raise HTTPException(409, "用户名已存在")
    conn.close()
    return {"ok": True, "message": "注册成功"}


@app.post("/api/login")
def login(body: LoginBody):
    conn = _conn()
    cur = _cur(conn)
    row = cur.execute(_q("SELECT * FROM users WHERE username = ?"), (body.username.strip(),)).fetchone()
    conn.close()
    if row is None:
        raise HTTPException(401, "用户名或密码错误")
    salt = base64.b64decode(row["salt"])
    if not hmac.compare_digest(_hash_password(body.password, salt), row["password_hash"]):
        raise HTTPException(401, "用户名或密码错误")
    if not row["active"]:
        raise HTTPException(403, "该账号已被禁用，请联系管理员")
    token = _make_token({"uid": row["id"], "role": "user", "exp": int(time.time()) + TOKEN_TTL})
    return {"ok": True, "token": token, "user": {
        "id": row["id"], "username": row["username"], "active": bool(row["active"]),
        "created_at": row["created_at"],
    }}


@app.get("/api/me")
def me(request: Request):
    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip() if auth else ""
    payload = _verify_token(token) if token else None
    if not payload or payload.get("role") != "user":
        raise HTTPException(401, "登录状态无效，请重新登录")
    conn = _conn()
    cur = _cur(conn)
    row = cur.execute(_q("SELECT * FROM users WHERE id = ?"), (payload["uid"],)).fetchone()
    conn.close()
    if row is None:
        raise HTTPException(401, "账号不存在")
    if not row["active"]:
        raise HTTPException(403, "该账号已被禁用，请联系管理员")
    return {"ok": True, "user": {
        "id": row["id"], "username": row["username"], "active": bool(row["active"]),
        "created_at": row["created_at"],
    }}


@app.post("/api/admin/login")
def admin_login(body: LoginBody):
    row = _get_admin_row()
    salt = base64.b64decode(row["salt"])
    if row["username"] != body.username.strip() or not hmac.compare_digest(
            _hash_password(body.password, salt), row["password_hash"]):
        raise HTTPException(401, "管理员账号或密码错误")
    token = _make_token({"uid": 1, "role": "admin", "exp": int(time.time()) + TOKEN_TTL})
    return {"ok": True, "token": token}


def _require_admin(request: Request):
    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip() if auth else ""
    payload = _verify_token(token) if token else None
    if not payload or payload.get("role") != "admin":
        raise HTTPException(401, "需要管理员权限")


@app.get("/api/admin/users")
def admin_users(request: Request):
    _require_admin(request)
    conn = _conn()
    cur = _cur(conn)
    rows = cur.execute(_q("SELECT id, username, active, created_at FROM users ORDER BY id DESC")).fetchall()
    conn.close()
    return {"ok": True, "users": [dict(r) for r in rows]}


@app.post("/api/admin/users/{uid}/status")
def admin_set_status(uid: int, body: StatusBody, request: Request):
    _require_admin(request)
    conn = _conn()
    cur = _cur(conn)
    cur.execute(_q("UPDATE users SET active = ? WHERE id = ?"), (1 if body.active else 0, uid))
    conn.commit()
    conn.close()
    if cur.rowcount == 0:
        raise HTTPException(404, "用户不存在")
    return {"ok": True}


@app.get("/api/health")
def health():
    return {"ok": True, "service": "ai-song-studio-server", "time": time.strftime("%Y-%m-%d %H:%M:%S")}


@app.get("/admin", response_class=HTMLResponse)
def admin_page():
    with open(os.path.join(BASE_DIR, "admin.html"), "r", encoding="utf-8") as f:
        return f.read()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
