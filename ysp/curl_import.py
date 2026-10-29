"""把抓包得到的 cURL / 原始 HTTP 请求解析成易校园直连所需参数。

支持三种粘贴方式：
  1. Chrome「Copy as cURL (bash)」/「Copy as cURL (cmd)」
  2. 原始 HTTP 请求（请求行 + Header + 空行 + body）
  3. 只贴 body / 只贴 URL / 只贴 Cookie（能解析多少算多少）

只做解析，不发网络请求；解析结果交给 ysp.direct 去验证和保存。
"""
from __future__ import annotations

import json
import re
import shlex
from urllib.parse import parse_qs, urlparse

from .xiaofubao import normalize_cookie

DEFAULT_HOST = "application.xiaofubao.com"
DEFAULT_PATH = "/app/electric/queryRoomSurplus"

ROOM_ALIASES: dict[str, tuple[str, ...]] = {
    "area_id": ("areaNo", "areaId", "areaCode", "campusNo"),
    "building_code": ("buildNo", "buildId", "buildingNo", "buildCode", "buildingCode"),
    "floor_code": ("floorNo", "floorId", "floorCode"),
    "room_code": ("roomNo", "roomId", "roomCode"),
    "area_name": ("areaName", "campusName"),
    "building_name": ("buildName", "buildingName"),
    "room_name": ("roomName", "roomFullName"),
}
YM_ALIASES = ("ymId", "ymid", "ym_id", "YMID", "userId", "userNo",
              "custId", "customerId", "personId")

# cURL 里常见但不需要值的开关；遇到时直接跳过，避免把后面的值当成 URL
_CURL_FLAGS = {
    "--compressed", "--insecure", "-k", "-s", "--silent", "-S", "--show-error",
    "-L", "--location", "--http1.1", "--http2", "--no-buffer", "-N",
}


def parse_request(text: str) -> dict:
    """解析 cURL / 原始请求，返回 cookie、ym_id、room、body 等字段。"""
    text = (text or "").strip()
    if not text:
        raise ValueError("内容为空")
    low = text[:400].lower()
    if low.startswith("curl") or "curl " in low:
        return _parse_curl(text)
    if re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+\s+HTTP/", text, re.I):
        return _parse_raw_http(text)
    return _parse_loose(text)


# ------------------------------------------------------------------ cURL

def _parse_curl(text: str) -> dict:
    # Chrome 的 bash 版用反斜杠续行，PowerShell/cmd 版可能用反引号或 ^
    text = re.sub(r"\\\r?\n", " ", text)
    text = re.sub(r"`\r?\n", " ", text)
    text = re.sub(r"\^\r?\n", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        return _parse_curl_regex(text)

    url = ""
    method = "POST"
    headers: dict[str, str] = {}
    body_parts: list[str] = []
    i = 1
    while i < len(tokens):
        t = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
        if t in ("-X", "--request"):
            method = nxt.upper()
            i += 2
        elif t in ("-H", "--header"):
            _add_header(headers, nxt)
            i += 2
        elif t in ("-b", "--cookie"):
            headers["cookie"] = nxt.strip()
            i += 2
        elif t in ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode"):
            body_parts.append(nxt)
            i += 2
        elif t == "--url":
            url = nxt
            i += 2
        elif t in ("-A", "--user-agent"):
            headers["user-agent"] = nxt
            i += 2
        elif t in ("-o", "--output"):
            i += 2
        elif t in _CURL_FLAGS:
            i += 1
        elif t.startswith("http://") or t.startswith("https://"):
            url = t
            i += 1
        elif t.startswith("-"):
            i += 1
        else:
            i += 1

    if not url:
        # 有些复制格式把 URL 放在 --url 之外，用正则兜底
        m = re.search(r"https?://[^\s'\"\\]+", text)
        if m:
            url = m.group(0)
    body = "&".join(p for p in body_parts if p)
    return _result("curl", url, method, headers, body)


def _parse_curl_regex(text: str) -> dict:
    """shlex 失败时的兜底：只处理最常见的 --data-raw / -H / URL。"""
    m = re.search(r"https?://[^\s'\"\\]+", text)
    url = m.group(0) if m else ""
    headers: dict[str, str] = {}
    for hm in re.finditer(r"(?:-H|--header)\s+['\"]([^'\"]+)['\"]", text):
        _add_header(headers, hm.group(1))
    body = ""
    for bm in re.finditer(
            r"(?:-d|--data|--data-raw|--data-binary|--data-urlencode)\s+['\"](.+?)['\"](?:\s|$)",
            text, re.S):
        body = (body + "&" if body else "") + bm.group(1)
    return _result("curl", url, "POST", headers, body)


# ------------------------------------------------------------------ raw HTTP

def _parse_raw_http(text: str) -> dict:
    parts = re.split(r"\r?\n\r?\n", text, maxsplit=1)
    head = parts[0]
    body = parts[1] if len(parts) > 1 else ""
    lines = head.splitlines()
    m = re.match(r"^(\w+)\s+(\S+)\s+HTTP/", lines[0]) if lines else None
    if not m:
        raise ValueError("不是有效的 HTTP 请求")
    method, path = m.group(1).upper(), m.group(2)
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            _add_header(headers, line)
    host = headers.get("host") or DEFAULT_HOST
    url = path if path.startswith("http") else f"https://{host}{path}"
    return _result("http", url, method, headers, body.strip())


# ------------------------------------------------------------------ loose

def _parse_loose(text: str) -> dict:
    url = ""
    m = re.search(r"https?://[^\s'\"\\]+", text)
    if m:
        url = m.group(0)
    headers: dict[str, str] = {}
    cm = re.search(r"(?:cookie\s*:\s*)([^\r\n]+)", text, re.I)
    if cm:
        headers["cookie"] = cm.group(1).strip()
    sm = re.search(r"shiroJID\s*=\s*([A-Za-z0-9\-._~%]+)", text, re.I)
    if sm and not headers.get("cookie"):
        headers["cookie"] = f"shiroJID={sm.group(1)}"
    body = ""
    if text.lstrip().startswith(("{", "[")):
        body = text
    else:
        # 看起来像表单 body
        if "=" in text and not url and not headers.get("cookie"):
            body = text
    if not (url or headers or body):
        # 只贴了一个 shiroJID 值
        s = text.strip().strip("'\"")
        if re.fullmatch(r"[A-Za-z0-9\-._~%]{16,}", s):
            headers["cookie"] = f"shiroJID={s}"
        else:
            raise ValueError("无法识别：请粘贴 cURL、原始 HTTP 请求或表单 body")
    return _result("loose", url or f"https://{DEFAULT_HOST}{DEFAULT_PATH}",
                   "POST", headers, body)


# ------------------------------------------------------------------ fields

def _add_header(headers: dict[str, str], line: str) -> None:
    k, _, v = (line or "").partition(":")
    if k.strip():
        headers[k.strip().lower()] = v.strip()


def _result(kind: str, url: str, method: str, headers: dict[str, str],
            body: str) -> dict:
    url = (url or "").strip().strip("'\"")
    if url and not url.startswith(("http://", "https://")):
        url = f"https://{DEFAULT_HOST}{url if url.startswith('/') else '/' + url}"
    cookie_raw = (headers.pop("cookie", "") or "").strip()
    cookie = normalize_cookie(cookie_raw) if cookie_raw else ""
    fields = _fields(url, body)
    ym_id = _pick(fields, YM_ALIASES)
    room = {k: _pick(fields, keys) for k, keys in ROOM_ALIASES.items()}
    room = {k: v for k, v in room.items() if v}
    return {
        "kind": kind,
        "url": url,
        "method": method,
        "headers": headers,
        "cookie": cookie,
        "cookie_present": bool(cookie),
        "ym_id": ym_id or "",
        "room": room,
        "body": body,
        "fields": {str(k): str(v) for k, v in fields.items()},
    }


def _fields(url: str, body: str) -> dict:
    out: dict = {}
    q = urlparse(url).query if url else ""
    if q:
        out.update({k: v[-1] for k, v in parse_qs(q).items()})
    b = (body or "").strip()
    if b:
        if b.startswith(("{", "[")):
            try:
                obj = json.loads(b)
            except ValueError:
                obj = None
            if isinstance(obj, dict):
                out.update(obj)
        else:
            out.update({k: v[-1] for k, v in parse_qs(b).items()})
    # 一层嵌套也翻出来（有些接口把参数包在 data 里）
    for v in list(out.values()):
        if isinstance(v, dict):
            out.update(v)
    return out


def _pick(fields: dict, keys: tuple[str, ...]) -> str:
    low = {str(k).lower(): v for k, v in fields.items()}
    for k in keys:
        v = low.get(k.lower())
        if v not in (None, "", [], {}):
            return str(v).strip()
    return ""
