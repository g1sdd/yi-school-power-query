"""`/direct` 的多用户存储：账号、浏览器令牌、房间、最近余额。

和现有单用户采集完全隔离 —— 用的是 `d` 前缀的新表，**不碰** `rooms` / `readings` /
`meta.session`，所以别人登录不会覆盖本站主人的 nofish 登录态。

存了什么（重要）：
  * 手机号、学校、ym_id —— 用来「下次打开还认得你」
  * 浏览器令牌的 **sha256**（原始令牌只在浏览器 localStorage 里）
  * shiroJID —— **AES-128-CTR + HMAC 加密**后存，密钥在 `data/direct.key`
  * 房间列表 + 最后一次查到的余额（只做展示，不当时序数据）
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from . import direct_login as dl
from .config import ROOT

SCHEMA = """
CREATE TABLE IF NOT EXISTS dusers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    phone       TEXT NOT NULL UNIQUE,
    school_code TEXT NOT NULL DEFAULT '',
    school_name TEXT NOT NULL DEFAULT '',
    ym_id       TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dsessions (
    token_hash  TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL,
    shiro_sealed TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    ip          TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS drooms (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    area_id       TEXT NOT NULL DEFAULT '',
    building_code TEXT NOT NULL DEFAULT '',
    floor_code    TEXT NOT NULL DEFAULT '',
    room_code     TEXT NOT NULL DEFAULT '',
    label         TEXT NOT NULL DEFAULT '',
    is_default    INTEGER NOT NULL DEFAULT 1,
    last_amount   REAL,
    last_surplus  REAL,
    last_query_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS drooms_key
    ON drooms(user_id, area_id, building_code, floor_code, room_code);
CREATE INDEX IF NOT EXISTS dsessions_user ON dsessions(user_id);
"""

def now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def ensure(conn: sqlite3.Connection) -> None:
    """建表（幂等）。代价只有一句 executescript，别做跨连接缓存，省得 id 复用时踩坑。"""
    conn.executescript(SCHEMA)
    conn.commit()


# ------------------------------------------------------------------ 密钥

_KEY_FILE = ROOT / "data" / "direct.key"


def key_path():
    return _KEY_FILE


def set_key_path(path) -> None:
    """测试/多实例部署时可换密钥位置。"""
    global _KEY_FILE
    _KEY_FILE = Path(path)


def secret_key() -> bytes:
    """读（或生成）本机加密密钥。丢了就等于所有已存登录失效，需要重新验证。"""
    try:
        raw = base64.b64decode(_KEY_FILE.read_text(encoding="ascii").strip())
        if len(raw) == 16:
            return raw
    except (OSError, ValueError):
        pass
    _KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    k = os.urandom(16)
    _KEY_FILE.write_text(base64.b64encode(k).decode("ascii"), encoding="ascii")
    try:  # 只给本用户读（Windows 上是 no-op，不报错就行）
        os.chmod(_KEY_FILE, 0o600)
    except OSError:
        pass
    return k


# ------------------------------------------------------------------ 账号

def upsert_user(conn: sqlite3.Connection, phone: str, school_code: str,
                school_name: str = "", ym_id: str = "") -> dict:
    ensure(conn)
    ts = now()
    row = conn.execute("SELECT * FROM dusers WHERE phone=?", (phone,)).fetchone()
    if row:
        conn.execute(
            "UPDATE dusers SET school_code=?, school_name=?, ym_id=?, last_seen=? WHERE id=?",
            (school_code or row["school_code"], school_name or row["school_name"],
             ym_id or row["ym_id"], ts, row["id"]))
        uid = row["id"]
    else:
        cur = conn.execute(
            "INSERT INTO dusers(phone, school_code, school_name, ym_id, created_at, last_seen)"
            " VALUES (?,?,?,?,?,?)",
            (phone, school_code, school_name, ym_id, ts, ts))
        uid = cur.lastrowid
    conn.commit()
    return get_user(conn, int(uid)) or {}


def get_user(conn: sqlite3.Connection, user_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM dusers WHERE id=?", (user_id,)).fetchone()
    return dict(row) if row else None


def get_user_by_phone(conn: sqlite3.Connection, phone: str) -> dict | None:
    row = conn.execute("SELECT * FROM dusers WHERE phone=?", (phone,)).fetchone()
    return dict(row) if row else None


def public_user(user: dict | None) -> dict:
    """给前端看的账号信息：手机号打码，不返回 ym_id。"""
    if not user:
        return {}
    return {
        "phone": dl.mask_phone(str(user.get("phone") or "")),
        "school_code": str(user.get("school_code") or ""),
        "school_name": str(user.get("school_name") or ""),
    }


# ------------------------------------------------------------------ 令牌

TOKEN_DAYS = 30


def hash_token(token: str) -> str:
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def create_session(conn: sqlite3.Connection, user_id: int, shiro_jid: str = "",
                   days: int = TOKEN_DAYS, ip: str = "") -> tuple[str, dict]:
    """发一个新令牌，顺便把 shiroJID 加密存进去。返回 (原始令牌, 会话行)。"""
    ensure(conn)
    token = new_token()
    th = hash_token(token)
    ts = now()
    exp = (datetime.now() + timedelta(days=int(days))).isoformat(timespec="seconds")
    sealed = dl.seal(shiro_jid, secret_key()) if shiro_jid else ""
    conn.execute(
        "INSERT INTO dsessions(token_hash, user_id, shiro_sealed, created_at, last_seen,"
        " expires_at, ip) VALUES (?,?,?,?,?,?,?)",
        (th, int(user_id), sealed, ts, ts, exp, ip))
    conn.commit()
    return token, get_session(conn, th) or {}


def get_session(conn: sqlite3.Connection, token_hash: str) -> dict | None:
    ensure(conn)
    row = conn.execute(
        "SELECT s.*, u.phone, u.school_code, u.school_name, u.ym_id"
        " FROM dsessions s JOIN dusers u ON u.id = s.user_id"
        " WHERE s.token_hash=?", (token_hash,)).fetchone()
    if not row:
        return None
    out = dict(row)
    if out.get("expires_at") and out["expires_at"] <= now():
        conn.execute("DELETE FROM dsessions WHERE token_hash=?", (token_hash,))
        conn.commit()
        return None
    return out


def touch_session(conn: sqlite3.Connection, token_hash: str, days: int = TOKEN_DAYS) -> None:
    exp = (datetime.now() + timedelta(days=int(days))).isoformat(timespec="seconds")
    conn.execute("UPDATE dsessions SET last_seen=?, expires_at=? WHERE token_hash=?",
                 (now(), exp, token_hash))
    conn.commit()


def set_shiro(conn: sqlite3.Connection, token_hash: str, shiro_jid: str) -> None:
    sealed = dl.seal(shiro_jid, secret_key()) if shiro_jid else ""
    conn.execute("UPDATE dsessions SET shiro_sealed=? WHERE token_hash=?", (sealed, token_hash))
    conn.commit()


def get_shiro(conn: sqlite3.Connection, row: dict) -> str:
    sealed = str(row.get("shiro_sealed") or "")
    if not sealed:
        return ""
    try:
        return dl.unseal(sealed, secret_key())
    except dl.LoginError:
        return ""


def delete_session(conn: sqlite3.Connection, token_hash: str) -> None:
    conn.execute("DELETE FROM dsessions WHERE token_hash=?", (token_hash,))
    conn.commit()


def purge(conn: sqlite3.Connection) -> int:
    ensure(conn)
    cur = conn.execute("DELETE FROM dsessions WHERE expires_at <= ?", (now(),))
    conn.commit()
    return cur.rowcount or 0


# ------------------------------------------------------------------ 房间

def save_rooms(conn: sqlite3.Connection, user_id: int, rooms: list[dict]) -> list[dict]:
    """把 queryBind 的结果存成这个账号的房间（重复登录不重复插）。"""
    ensure(conn)
    seen = set()
    for i, r in enumerate(rooms):
        key = (str(r.get("area_id") or ""), str(r.get("building_code") or ""),
               str(r.get("floor_code") or ""), str(r.get("room_code") or ""))
        seen.add(key)
        label = str(r.get("label") or r.get("room_name") or "")
        conn.execute(
            "INSERT INTO drooms(user_id, area_id, building_code, floor_code, room_code,"
            " label, is_default) VALUES (?,?,?,?,?,?,?)"
            " ON CONFLICT(user_id, area_id, building_code, floor_code, room_code)"
            " DO UPDATE SET label=excluded.label",
            (int(user_id), *key, label, 1 if i == 0 else 0))
    # 上游解绑的房间就别留着了
    rows = conn.execute("SELECT id, area_id, building_code, floor_code, room_code"
                        " FROM drooms WHERE user_id=?", (int(user_id),)).fetchall()
    for row in rows:
        if (row["area_id"], row["building_code"], row["floor_code"],
                row["room_code"]) not in seen:
            conn.execute("DELETE FROM drooms WHERE id=?", (row["id"],))
    conn.commit()
    return list_rooms(conn, user_id)


def list_rooms(conn: sqlite3.Connection, user_id: int) -> list[dict]:
    ensure(conn)
    rows = conn.execute(
        "SELECT * FROM drooms WHERE user_id=? ORDER BY is_default DESC, id",
        (int(user_id),)).fetchall()
    return [{
        "id": r["id"],
        "area_id": r["area_id"],
        "building_code": r["building_code"],
        "floor_code": r["floor_code"],
        "room_code": r["room_code"],
        "label": r["label"] or r["room_code"],
        "last_amount": r["last_amount"],
        "last_surplus": r["last_surplus"],
        "last_query_at": r["last_query_at"],
    } for r in rows]


def update_balance(conn: sqlite3.Connection, room_id: int,
                   amount: float | None, surplus: float | None) -> None:
    conn.execute("UPDATE drooms SET last_amount=?, last_surplus=?, last_query_at=? WHERE id=?",
                 (amount, surplus, now(), int(room_id)))
    conn.commit()


def stats(conn: sqlite3.Connection) -> dict[str, Any]:
    ensure(conn)
    one = lambda sql: conn.execute(sql).fetchone()[0]  # noqa: E731
    return {
        "users": one("SELECT COUNT(*) FROM dusers"),
        "sessions": one("SELECT COUNT(*) FROM dsessions"),
        "rooms": one("SELECT COUNT(*) FROM drooms"),
    }
