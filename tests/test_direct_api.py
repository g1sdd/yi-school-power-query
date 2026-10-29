"""直连一次性查询的 HTTP 接口测试：/api/direct/*（上游由本地 mock 模拟）。

跑法::

    python -m unittest discover -s tests -v
    python tests/test_direct_api.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for p in (str(ROOT), str(Path(__file__).resolve().parent)):
    if p not in sys.path:
        sys.path.insert(0, p)

from test_direct_login import MockUpstream  # noqa: E402
from ysp import direct_login as dl  # noqa: E402
from ysp import direct_store as dstore  # noqa: E402
from ysp import server as S  # noqa: E402


def post(url: str, body: dict, token: str = "") -> tuple[int, dict]:
    data = json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-YS-Token"] = token
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8") or "{}")


def get(url: str, token: str = "") -> tuple[int, dict]:
    req = urllib.request.Request(url, headers={"X-YS-Token": token} if token else {})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.status, json.loads(r.read().decode("utf-8"))


class _FakeClient:
    """只为「两个人同时查」这个用例准备的最小替身。"""

    def __init__(self, balance: float):
        self.dev_id = "ym-fake"
        self.school_code = "10356"
        self.school_name = "中国计量大学"
        self.balance = balance

    def query_room_surplus(self, room: dict, shiro_jid: str = "") -> dict:
        return {
            "room_label": room.get("label", ""),
            "display_room_name": room.get("label", ""),
            "amount": self.balance,
            "surplus": 1.0,
            "is_show_money": 1,
            "is_show_surplus": 0,
            "data": {"amount": self.balance, "room": room.get("room_code")},
        }


class TestDirectAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mock = MockUpstream().__enter__()
        os.environ["YSP_YXY_COMPUS"] = cls.mock.base
        os.environ["YSP_YXY_AUTH"] = cls.mock.base
        os.environ["YSP_YXY_APPLICATION"] = cls.mock.base
        # 用临时库 + 临时密钥，别写到真实 data/power.db 里
        cls.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls._db_file = S.DB_FILE
        cls._key_file = dstore.key_path()
        S.DB_FILE = Path(cls.tmp.name) / "power.db"
        dstore.set_key_path(Path(cls.tmp.name) / "direct.key")
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), S.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.mock.__exit__(None, None, None)
        S.DB_FILE = cls._db_file
        dstore.set_key_path(cls._key_file)
        c = getattr(S._local, "conn", None)   # 关掉主线程那条连接，否则 Windows 删不掉临时库
        if c is not None:
            try:
                c.close()
            except Exception:  # noqa: BLE001
                pass
            S._local.conn = None
        for k in ("YSP_YXY_COMPUS", "YSP_YXY_AUTH", "YSP_YXY_APPLICATION"):
            os.environ.pop(k, None)
        cls.tmp.cleanup()

    def setUp(self):
        # 每个用例都从干净的内存会话 / 限流计数开始
        S.reset_direct_state()
        self.mock.require_json_bind = False
        self.mock.shiro = "fake-shiro-jid-0001"
        self.base = f"http://127.0.0.1:{self.port}"

    # -- 帮助函数
    def _start(self, school="10356"):
        code, j = post(self.base + "/api/direct/start", {"school_code": school})
        self.assertEqual(code, 200, j)
        self.assertTrue(j["session_id"])
        self.assertTrue(j["captcha"]["data_uri"].startswith("data:image/png;base64,"))
        return j

    def _send(self, sid, phone=None, captcha=None):
        return post(self.base + "/api/direct/send-code", {
            "session_id": sid,
            "phone": phone or self.mock.phone,
            "captcha": self.mock.captcha_code if captcha is None else captcha,
        })

    # -- 用例
    def test_full_flow(self):
        j = self._start()
        sid = j["session_id"]
        # 手机号不出现在响应里（只有打码）
        self.assertNotIn(self.mock.phone, json.dumps(j))

        code, j2 = self._send(sid)
        self.assertEqual(code, 200, j2)
        self.assertEqual(j2["phone"], "138****0000")
        self.assertEqual(j2["step"], "sent")

        code, j3 = post(self.base + "/api/direct/login",
                        {"session_id": sid, "sms_code": self.mock.sms_code})
        self.assertEqual(code, 200, j3)
        self.assertEqual(len(j3["rooms"]), 1)
        self.assertEqual(j3["rooms"][0]["room_code"], "0101")
        self.assertEqual(j3["step"], "logged_in")

        code, j4 = post(self.base + "/api/direct/query",
                        {"session_id": sid, "room_index": 0})
        self.assertEqual(code, 200, j4)
        self.assertEqual(j4["balance"]["amount"], 88.88)
        self.assertEqual(j4["balance"]["surplus"], 123.4)
        self.assertIn("0101", j4["balance"]["room_label"])
        self.assertEqual(j4["raw"]["isShowMoney"], 0)

        # 凭据绝不出现在任何响应里
        blob = json.dumps([j, j2, j3, j4], ensure_ascii=False)
        for secret in (self.mock.shiro, self.mock.uid, self.mock.phone,
                       self.mock.security_token, self.mock.sms_code):
            self.assertNotIn(secret, blob)

    def test_captcha_required(self):
        sid = self._start()["session_id"]
        code, j = self._send(sid, captcha="")
        self.assertEqual(code, 400)
        self.assertEqual(j["kind"], "captcha")
        self.assertIn("图形验证码", j["error"])

    def test_wrong_captcha(self):
        sid = self._start()["session_id"]
        code, j = self._send(sid, captcha="0000")
        self.assertEqual(code, 400)
        self.assertEqual(j["kind"], "captcha")

    def test_rate_limit(self):
        sid = self._start()["session_id"]
        code, _ = self._send(sid)
        self.assertEqual(code, 200)
        code, j = self._send(sid)
        self.assertEqual(code, 429)
        self.assertEqual(j["kind"], "limit")

    def test_bad_phone(self):
        sid = self._start()["session_id"]
        code, j = self._send(sid, phone="12345")
        self.assertEqual(code, 400)
        self.assertEqual(j["kind"], "phone")

    def test_wrong_sms_code(self):
        sid = self._start()["session_id"]
        self.assertEqual(self._send(sid)[0], 200)
        code, j = post(self.base + "/api/direct/login",
                       {"session_id": sid, "sms_code": "000000"})
        self.assertEqual(code, 400)
        self.assertEqual(j["kind"], "code")

    def test_expired_or_unknown_session(self):
        code, j = post(self.base + "/api/direct/login",
                       {"session_id": "not-a-real-session", "sms_code": "123456"})
        self.assertEqual(code, 400)
        self.assertEqual(j["kind"], "expired")
        self.assertIn("会话", j["error"])

    def test_captcha_refresh(self):
        sid = self._start()["session_id"]
        code, j = post(self.base + "/api/direct/captcha", {"session_id": sid})
        self.assertEqual(code, 200, j)
        self.assertTrue(j["captcha"]["data_uri"])
        self.assertEqual(j["step"], "started")

    def test_status_and_close(self):
        sid = self._start()["session_id"]
        code, j = get(self.base + f"/api/direct/status?session_id={sid}")
        self.assertEqual(code, 200)
        self.assertTrue(j["exists"])

        code, _ = post(self.base + "/api/direct/close", {"session_id": sid})
        self.assertEqual(code, 200)
        code, j = get(self.base + f"/api/direct/status?session_id={sid}")
        self.assertFalse(j["exists"])

    def test_bad_school_code(self):
        # 明确填了学校名但列表里没有 → 报错，不要偷偷换成默认学校
        code, j = post(self.base + "/api/direct/start", {"school": "不存在的学校"})
        self.assertEqual(code, 400)
        self.assertIn("学校", j["error"])
        # 列表外的代码（学校可能没收录）允许手填，只要长得像代码
        code, j = post(self.base + "/api/direct/start", {"school_code": "qt999"})
        self.assertEqual(code, 200, j)
        self.assertEqual(j["school_code"], "qt999")

    def test_start_throttled_per_ip(self):
        S.direct_throttle().per_hour = 2
        self._start()
        self._start()
        code, j = post(self.base + "/api/direct/start", {"school_code": "10356"})
        self.assertEqual(code, 429)
        self.assertEqual(j["kind"], "limit")

    def test_session_ttl_purge(self):
        """TTL 到期后必须报「会话过期」，而不是悄悄复用。"""
        store = S.direct_sessions()
        s = store.create("ym-test", "10356")
        s.ttl = 0
        import time as _t
        _t.sleep(0.01)
        with self.assertRaises(dl.LoginError) as cm:
            store.get(s.sid)
        self.assertEqual(cm.exception.kind, "expired")
        self.assertEqual(store.purge(), 0)

    # ---------------------------------------------------------- 持久登录

    def _login_and_get_token(self) -> dict:
        sid = self._start()["session_id"]
        self.assertEqual(self._send(sid)[0], 200)
        code, j = post(self.base + "/api/direct/login",
                       {"session_id": sid, "sms_code": self.mock.sms_code})
        self.assertEqual(code, 200, j)
        self.assertTrue(j.get("token"), j)
        return j

    def test_login_gives_token_and_user(self):
        j = self._login_and_get_token()
        self.assertEqual(j["user"]["phone"], "138****0000")
        self.assertEqual(j["user"]["school_name"], "中国计量大学")
        self.assertIn("expires_at", j)
        # 令牌不能出现在会话快照里，也不能等于上游票据
        self.assertNotEqual(j["token"], self.mock.shiro)

    def test_token_query_without_sms(self):
        tok = self._login_and_get_token()["token"]
        # 完全不带 session_id，只靠浏览器令牌
        code, j = post(self.base + "/api/direct/query", {"room_index": 0}, token=tok)
        self.assertEqual(code, 200, j)
        self.assertEqual(j["balance"]["amount"], 88.88)
        self.assertEqual(j["room"]["room_code"], "0101")
        # 余额记到数据库的房间里（下次打开能先看到上次的数）
        conn = S.conn()
        row = dstore.get_session(conn, dstore.hash_token(tok))
        rooms = dstore.list_rooms(conn, row["user_id"])
        self.assertEqual(rooms[0]["last_amount"], 88.88)

    def test_session_endpoint(self):
        tok = self._login_and_get_token()["token"]
        code, j = get(self.base + "/api/direct/session", token=tok)
        self.assertEqual(code, 200, j)
        self.assertTrue(j["exists"])
        self.assertTrue(j["has_login"])
        self.assertEqual(j["rooms"][0]["room_code"], "0101")
        self.assertEqual(j["user"]["phone"], "138****0000")
        blob = json.dumps(j, ensure_ascii=False)
        for secret in (self.mock.shiro, self.mock.uid, self.mock.phone):
            self.assertNotIn(secret, blob)

    def test_logout_drops_token(self):
        tok = self._login_and_get_token()["token"]
        code, _ = post(self.base + "/api/direct/logout", {}, token=tok)
        self.assertEqual(code, 200)
        code, j = get(self.base + "/api/direct/session", token=tok)
        self.assertFalse(j["exists"])
        code, j = post(self.base + "/api/direct/query", {"room_index": 0}, token=tok)
        self.assertEqual(code, 400)
        self.assertEqual(j["kind"], "relogin")

    def test_upstream_session_dead_asks_relogin(self):
        """上游把票据废了（204 请重新登录）→ 令牌还在，但要重新验证一次。"""
        tok = self._login_and_get_token()["token"]
        self.mock.shiro = "rotated-on-upstream"      # 旧票据立刻失效
        code, j = post(self.base + "/api/direct/query", {"room_index": 0}, token=tok)
        self.assertEqual(code, 400)
        self.assertEqual(j["kind"], "relogin")
        # 第二轮直接说「需要重新验证」，不会反复拿废票据撞上游
        code, j = post(self.base + "/api/direct/query", {"room_index": 0}, token=tok)
        self.assertEqual(j["kind"], "relogin")
        code, j = get(self.base + "/api/direct/session", token=tok)
        self.assertTrue(j["exists"])
        self.assertFalse(j["has_login"])
        self.assertEqual(j["rooms"][0]["room_code"], "0101")

    def test_second_user_keeps_first_users_rooms(self):
        """同一台机器上两个人先后登录，各自的房间都还在。"""
        self._login_and_get_token()
        conn = S.conn()
        u2 = dstore.upsert_user(conn, "13900000001", "10346", "杭州师范大学", "uid-2")
        dstore.save_rooms(conn, u2["id"], [{
            "area_id": "9", "building_code": "b9", "floor_code": "f9",
            "room_code": "0901", "label": "另一个人的寝室"}])
        u1 = dstore.get_user_by_phone(conn, self.mock.phone) or {}
        rooms1 = dstore.list_rooms(conn, u1.get("id", 0))
        rooms2 = dstore.list_rooms(conn, u2["id"])
        self.assertEqual(rooms1[0]["room_code"], "0101")
        self.assertEqual(rooms2[0]["room_code"], "0901")

    # ---------------------------------------------------------- 学校

    def test_schools_endpoint(self):
        code, j = get(self.base + "/api/direct/schools")
        self.assertEqual(code, 200)
        names = [s["name"] for s in j["schools"]]
        self.assertIn("中国计量大学", names)
        self.assertEqual(j["default"], "10356")
        code, j = get(self.base + "/api/direct/schools?q=" + urllib.parse.quote("师范"))
        self.assertTrue(all("师范" in s["name"] for s in j["schools"]))
        self.assertTrue(j["schools"])

    def test_start_with_school_name(self):
        code, j = post(self.base + "/api/direct/start", {"school": "杭州师范大学"})
        self.assertEqual(code, 200, j)
        self.assertEqual(j["school_code"], "10346")
        # 名字认不出来 → 明确报错，不要偷偷用默认学校
        code, j = post(self.base + "/api/direct/start", {"school": "不存在的学校"})
        self.assertEqual(code, 400)
        self.assertIn("学校", j["error"])

    def test_limits_come_from_config(self):
        c = S.direct_cfg()
        self.assertEqual(c["school_code"], "10356")
        self.assertEqual(int(c["session_ttl_minutes"]), 30)
        self.assertIsInstance(S.direct_limiter(), dl.SendLimiter)

    # ---------------------------------------------------------- 多用户隔离

    def test_two_users_do_not_overwrite(self):
        """两个人同时查，各查各的：会话、寝室、余额都不会串。"""
        store = S.direct_sessions()
        a = store.create("ym-aaaa", "10356")
        a.phone, a.step = "13300000001", "logged_in"
        a.rooms = [{"room_code": "0101", "label": "A 的寝室", "area_id": "1",
                    "building_code": "b", "floor_code": "f"}]
        a.client = _FakeClient(11.11)

        b = store.create("ym-bbbb", "10356")
        b.phone, b.step = "13300000002", "logged_in"
        b.rooms = [{"room_code": "0101", "label": "B 的寝室", "area_id": "2",
                    "building_code": "c", "floor_code": "g"}]
        b.client = _FakeClient(22.22)

        self.assertNotEqual(a.sid, b.sid)

        code, ja = post(self.base + "/api/direct/query",
                        {"session_id": a.sid, "room_index": 0})
        self.assertEqual(code, 200, ja)
        self.assertEqual(ja["balance"]["amount"], 11.11)
        self.assertEqual(ja["room"]["room_code"], "0101")

        code, jb = post(self.base + "/api/direct/query",
                        {"session_id": b.sid, "room_index": 0})
        self.assertEqual(code, 200, jb)
        self.assertEqual(jb["balance"]["amount"], 22.22)
        self.assertEqual(jb["room"]["room_code"], "0101")

        # 各自的状态没被对方碰过
        self.assertEqual(a.phone, "13300000001")
        self.assertEqual(b.phone, "13300000002")
        self.assertEqual(a.rooms[0]["room_code"], "0101")
        self.assertEqual(b.rooms[0]["room_code"], "0101")

        # 用 A 的会话要 B 的序号越界 → 报错，不会拿到别人的房间
        code, j = post(self.base + "/api/direct/query",
                       {"session_id": b.sid, "room_index": 5})
        self.assertEqual(code, 400)
        self.assertEqual(j["kind"], "upstream")

        # 会话之间看不到对方的手机号
        _, sa = get(self.base + f"/api/direct/status?session_id={a.sid}")
        _, sb = get(self.base + f"/api/direct/status?session_id={b.sid}")
        self.assertEqual(sa["phone"], "133****0001")
        self.assertEqual(sb["phone"], "133****0002")

    def test_direct_flow_never_touches_login_session(self):
        """直连查询绝不写/清现有登录态 —— 别人用这个页面不会把你的登录顶掉。"""
        calls: list[tuple] = []
        orig_save, orig_clear = S.save_session, S.clear_session
        S.save_session = lambda *a, **k: calls.append(("save", a, k))
        S.clear_session = lambda *a, **k: calls.append(("clear", a, k))
        try:
            sid = self._start()["session_id"]
            self.assertEqual(self._send(sid)[0], 200)
            self.assertEqual(post(self.base + "/api/direct/login",
                                  {"session_id": sid,
                                   "sms_code": self.mock.sms_code})[0], 200)
            self.assertEqual(post(self.base + "/api/direct/query",
                                  {"session_id": sid, "room_index": 0})[0], 200)
            post(self.base + "/api/direct/close", {"session_id": sid})
        finally:
            S.save_session, S.clear_session = orig_save, orig_clear
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
