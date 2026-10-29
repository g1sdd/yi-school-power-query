"""直连易校园：把抓包请求导入成可用的 xiaofubao 会话。

流程：
  1. 解析 cURL / 原始 HTTP 请求（ysp.curl_import）
  2. 请求里带了 ymId + 房间参数就直接查一次余额；缺的再走 discover()
  3. 查询成功后把会话写进数据库（meta.session），并登记房间
  4. 返回上游原始 JSON，方便核对字段

不经过 tool.no-fish.cn，也不依赖任何第三方中转。
"""
from __future__ import annotations

import json
import urllib.parse
from datetime import datetime
from urllib.parse import parse_qs

from . import db, xiaofubao as xf
from .auth import save_session
from .curl_import import parse_request

ROOM_FIELDS = ("area_id", "building_code", "floor_code", "room_code",
               "area_name", "building_name", "room_name")


def _existing_room(conn, room_fields: dict) -> dict | None:
    rooms = db.list_rooms(conn)
    code = str(room_fields.get("room_code") or "")
    if code:
        for r in rooms:
            if str(r.get("room_code") or "") != code:
                continue
            bc = str(room_fields.get("building_code") or "")
            rbc = str(r.get("building_code") or "")
            if bc and rbc and bc != rbc:
                continue
            return r
        # 有明确 roomCode 但本地没有：这是另一个房间，不能拿唯一房间顶替
        return None
    if len(rooms) == 1:
        return rooms[0]
    return None


def merge_room(conn, parsed_room: dict, found: dict) -> dict:
    """请求体 > discover 结果 > 本地已有房间，依次补齐。"""
    out: dict = {}
    for k in ROOM_FIELDS:
        v = str((parsed_room or {}).get(k) or "").strip() or str((found or {}).get(k) or "")
        if v:
            out[k] = v
    ex = _existing_room(conn, out)
    if ex:
        for k in ("area_name", "building_name", "room_name"):
            if not out.get(k) and ex.get(k):
                out[k] = ex[k]
    return out


def _save_session(conn, cookie: str, ym_id: str, room_fields: dict,
                  endpoint: str = "", request_body: str = "") -> dict | None:
    save_session(conn, source_type="xiaofubao", cookie=cookie,
                 shiro_jid=xf.shiro_value(cookie),
                 ym_id=ym_id, logged_in_at=datetime.now().isoformat(timespec="seconds"),
                 need_relogin=False, endpoint=endpoint, request_body=request_body,
                 **room_fields)

    room = None
    if room_fields.get("room_code") or room_fields.get("room_name"):
        ex = _existing_room(conn, room_fields)
        label = ""
        if ex:
            label = str(ex.get("label") or "")
        if not label:
            label = f"{room_fields.get('building_name', '')} {room_fields.get('room_name', '')}".strip()
        label = label or "我的寝室"
        key = (ex or {}).get("room_key") or "-".join(str(x) for x in (
            room_fields.get("area_id") or "0",
            room_fields.get("building_code") or room_fields.get("building_name") or "0",
            room_fields.get("floor_code") or "0",
            room_fields.get("room_code") or room_fields.get("room_name") or "0",
        ))
        prev = ex or (db.list_rooms(conn) or [{}])[0]
        room = {
            "room_key": key,
            "label": label,
            "school_code": prev.get("school_code", ""),
            "school_name": prev.get("school_name", ""),
            "area_id": room_fields.get("area_id", ""),
            "area_name": room_fields.get("area_name", ""),
            "building_code": room_fields.get("building_code", ""),
            "building_name": room_fields.get("building_name", ""),
            "floor_code": room_fields.get("floor_code", ""),
            "floor_name": prev.get("floor_name", ""),
            "room_code": room_fields.get("room_code", ""),
            "room_name": room_fields.get("room_name", ""),
            "unit_price": float(prev.get("unit_price", 0.538) or 0.538),
            "warn_kwh": float(prev.get("warn_kwh", 20) or 20),
            "critical_kwh": float(prev.get("critical_kwh", 5) or 5),
        }
        db.upsert_room(conn, room)
        save_session(conn, room_key=key, room_label=label)
    return room


def _replay(parsed: dict, cookie: str):
    """按抓到的原请求重放一次（不猜接口、不改字段）。"""
    url = str(parsed.get("url") or "")
    if "application.xiaofubao.com" not in url:
        raise xf.UpstreamError("抓到的请求不是易校园电费接口（application.xiaofubao.com）")
    # 允许测试/代理把 BASE 指到本地 mock；生产环境 BASE 就是真实上游
    p = urllib.parse.urlsplit(url)
    b = urllib.parse.urlsplit(xf.BASE)
    url = urllib.parse.urlunsplit((b.scheme, b.netloc, p.path, p.query, p.fragment))
    method = str(parsed.get("method") or "POST").upper()
    body = str(parsed.get("body") or "")
    if method == "GET":
        return xf._http(url, cookie, body=None, timeout=25)
    if body.lstrip().startswith(("{", "[")):
        raise xf.UpstreamError("目前只支持表单请求（application/x-www-form-urlencoded）")
    form = {k: v[-1] for k, v in parse_qs(body).items()}
    return xf._http(url, cookie, body=form, timeout=25)


def import_request(conn, text: str, save: bool = True) -> dict:
    """解析 + 按原请求重放一次；save=True 时写入会话/房间。

    关键：不把请求改写成老接口。抓到的是 queryRoomSurplus 就按
    queryRoomSurplus 的 URL/body 原样重放，成功后再把这条请求模板存进
    会话，后续采集继续用它。
    """
    parsed = parse_request(text)
    cookie = str(parsed.get("cookie") or "")
    if not cookie:
        raise xf.UpstreamError("没找到 Cookie: shiroJID。请复制包含 Cookie 的请求，"
                               "不要只复制响应。")

    ym_id = str(parsed.get("ym_id") or "").strip()
    room = merge_room(conn, parsed.get("room") or {}, {})
    if not room.get("room_code"):
        ex = _existing_room(conn, room)
        if ex:
            room = merge_room(conn, room, {k: ex.get(k, "") for k in ROOM_FIELDS})
    if not room.get("room_code"):
        raise xf.UpstreamError("请求里没有房间参数（areaId/buildingCode/floorCode/roomCode），"
                               "无法保存为采集房间。请复制 queryRoomSurplus 那条请求。")

    raw = _replay(parsed, cookie)
    res = xf.unwrap(raw, "抓包请求")
    data = res.data if isinstance(res.data, dict) else {}
    display = str(data.get("displayRoomName") or "").strip()
    if display and not room.get("room_name"):
        # queryRoomSurplus 会带回完整房间名；没有本地房间可复用时用它当标签
        room["room_name"] = display

    saved_room = _save_session(
        conn, cookie, ym_id, room,
        endpoint=str(parsed.get("url") or ""),
        request_body=str(parsed.get("body") or ""),
    ) if save else None
    return {
        "ok": True,
        "kind": parsed.get("kind"),
        "url": parsed.get("url"),
        "ym_id": ym_id,
        "room": saved_room or room,
        "raw": raw,
        "data": res.data,
        "cookie_present": True,
    }
