"""采集走直连（source.type=direct）的测试：轮询、失效回退、同寝室多账号不重复。

跑法::

    python -m unittest discover -s tests -v
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for p in (str(ROOT), str(Path(__file__).resolve().parent)):
    if p not in sys.path:
        sys.path.insert(0, p)

from test_direct_login import MockUpstream  # noqa: E402
from ysp import collect, db  # noqa: E402
from ysp import direct_login as dl  # noqa: E402
from ysp import direct_store as dstore  # noqa: E402
from ysp.adapters.base import DirectAdapter, SourceError, build_adapter  # noqa: E402

ROOM = {"room_key": "1000000000000001-b0001-f01-0101",
        "area_id": "1000000000000001", "building_code": "b0001",
        "floor_code": "f01", "room_code": "0101"}
ROOM_LABEL = "示例校区 1 号楼 0101 室"


def _cfg(db_path: str) -> dict:
    return {
        "source": {"type": "direct", "timeout": 10, "strict_tls": False},
        "direct": {"verify_tls": False, "timeout": 10},
        "db": {"path": db_path},
        "collect": {"retry": 1, "retry_delay_seconds": 0},
        "alerts": {"enabled": False},
        "rooms": [],
    }


class TestDirectCollect(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mock = MockUpstream().__enter__()
        os.environ["YSP_YXY_COMPUS"] = cls.mock.base
        os.environ["YSP_YXY_AUTH"] = cls.mock.base
        os.environ["YSP_YXY_APPLICATION"] = cls.mock.base

    @classmethod
    def tearDownClass(cls):
        cls.mock.__exit__(None, None, None)
        for k in ("YSP_YXY_COMPUS", "YSP_YXY_AUTH", "YSP_YXY_APPLICATION"):
            os.environ.pop(k, None)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = str(Path(self.tmp.name) / "power.db")
        self._key = dstore.key_path()
        dstore.set_key_path(Path(self.tmp.name) / "direct.key")
        self.cfg = _cfg(self.db_path)
        self.conn = db.connect(Path(self.db_path))
        self.mock.accept_shiros = set()
        self.mock.requests.clear()

    def tearDown(self):
        self.conn.close()
        dstore.set_key_path(self._key)
        self.tmp.cleanup()

    # -- 帮助函数
    def _user(self, phone: str, shiro: str = "") -> tuple[dict, str]:
        u = dstore.upsert_user(self.conn, phone, "10356", "中国计量大学", "uid-" + phone[-4:])
        dstore.save_rooms(self.conn, u["id"], [dict(ROOM, label=ROOM_LABEL)])
        token, row = dstore.create_session(self.conn, u["id"], shiro or ("shiro-" + phone[-4:]),
                                           days=30)
        return u, token

    def _shiros(self) -> list[str]:
        out = []
        for r in self.conn.execute("SELECT token_hash, shiro_sealed FROM dsessions"):
            shiro = dstore.get_shiro(self.conn, dict(r))
            if shiro:
                out.append(shiro)
        return sorted(out)

    # -- 用例
    def test_room_registered_once_for_two_users(self):
        self._user("13800000001")
        self._user("13800000002")
        self.assertEqual(dstore.stats(self.conn)["users"], 2)
        self.assertEqual(dstore.stats(self.conn)["rooms"], 2)   # 每人一行 drooms

        added = dstore.ensure_local_rooms(self.conn)
        self.assertEqual(added, 1)                              # 采集用的 rooms 只有一行
        rooms = db.list_rooms(self.conn)
        self.assertEqual(len(rooms), 1)
        self.assertEqual(rooms[0]["room_key"], "1000000000000001-b0001-f01-0101")

        # 再跑一次不会重复登记
        self.assertEqual(dstore.ensure_local_rooms(self.conn), 0)

    def test_sessions_rotate(self):
        self._user("13800000001", "shiro-aaaa")
        self._user("13800000002", "shiro-bbbb")
        a = [x["shiro"] for x in dstore.room_sessions(self.conn, ROOM)]
        b = [x["shiro"] for x in dstore.room_sessions(self.conn, ROOM)]
        c = [x["shiro"] for x in dstore.room_sessions(self.conn, ROOM)]
        self.assertEqual(len(a), 2)
        self.assertEqual(set(a), {"shiro-aaaa", "shiro-bbbb"})
        self.assertNotEqual(a, b)          # 下一轮换了起点
        self.assertEqual(a, c)             # 两人一轮，回到原点

    def test_no_rotation_keeps_order(self):
        self._user("13800000001", "shiro-aaaa")
        self._user("13800000002", "shiro-bbbb")
        first = [x["shiro"] for x in dstore.room_sessions(self.conn, ROOM, rotate=False)]
        for _ in range(3):
            got = [x["shiro"] for x in dstore.room_sessions(self.conn, ROOM, rotate=False)]
            self.assertEqual(got, first)

    def test_fetch_uses_rotating_account(self):
        self._user("13800000001", "shiro-aaaa")
        self._user("13800000002", "shiro-bbbb")
        self.mock.accept_shiros = {"shiro-aaaa", "shiro-bbbb"}
        adapter = DirectAdapter(self.cfg, conn=self.conn)

        used = []
        for _ in range(4):
            r = adapter.fetch(ROOM)
            self.assertEqual(r.unit, "cny")
            self.assertAlmostEqual(r.balance_cny, 88.88, places=2)
            cookie = self.mock.requests[-1]["headers"].get("Cookie", "")
            used.append(cookie)
        # 四个请求轮着用两个账号：相邻两次一定不是同一个
        self.assertEqual(len({u for u in used}), 2)
        for i in range(1, len(used)):
            self.assertNotEqual(used[i], used[i - 1])

    def test_dead_session_falls_back(self):
        _ua, ta = self._user("13800000001", "shiro-aaaa")   # 假设这个已被上游作废
        _ub, tb = self._user("13800000002", "shiro-bbbb")
        self.mock.accept_shiros = {"shiro-bbbb"}
        adapter = DirectAdapter(self.cfg, conn=self.conn)

        cands = [
            {"user_id": 1, "phone": "13800000001", "school_code": "10356",
             "school_name": "中国计量大学", "token_hash": dstore.hash_token(ta),
             "shiro": "shiro-aaaa"},
            {"user_id": 2, "phone": "13800000002", "school_code": "10356",
             "school_name": "中国计量大学", "token_hash": dstore.hash_token(tb),
             "shiro": "shiro-bbbb"},
        ]
        from unittest import mock as um
        with um.patch.object(dstore, "room_sessions", return_value=cands):
            r = adapter.fetch(ROOM)                 # 先试 aaaa 失败，自动换 bbbb
        self.assertAlmostEqual(r.balance_cny, 88.88, places=2)
        self.assertEqual(self._shiros(), ["shiro-bbbb"])   # 失效的那条被清掉
        self.assertFalse(adapter.need_relogin)             # 还有可用账号，不算要重登

    def test_all_sessions_dead(self):
        self._user("13800000001", "shiro-aaaa")
        self._user("13800000002", "shiro-bbbb")
        self.mock.accept_shiros = {"someone-else"}
        adapter = DirectAdapter(self.cfg, conn=self.conn)
        with self.assertRaises(SourceError):
            adapter.fetch(ROOM)
        self.assertTrue(adapter.need_relogin)
        self.assertEqual(self._shiros(), [])

    def test_no_session_at_all(self):
        dstore.upsert_user(self.conn, "13800000003", "10356")
        adapter = DirectAdapter(self.cfg, conn=self.conn)
        with self.assertRaises(SourceError) as cm:
            adapter.fetch(ROOM)
        self.assertIn("登录", str(cm.exception))

    def test_collect_once_writes_one_reading(self):
        """两个人绑同一个寝室 → 采集只写一条读数，room_key 唯一。"""
        self._user("13800000001", "shiro-aaaa")
        self._user("13800000002", "shiro-bbbb")
        self.mock.accept_shiros = {"shiro-aaaa", "shiro-bbbb"}

        res = collect.collect_once(self.cfg, verbose=False, run_alerts=False)
        self.assertTrue(res.get("ok"), res)
        self.assertEqual(len(res["results"]), 1)
        self.assertTrue(res["results"][0]["inserted"])

        rows = self.conn.execute(
            "SELECT ts, balance_cny, source FROM readings"
            " WHERE room_key='1000000000000001-b0001-f01-0101' ORDER BY ts").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source"], "direct")
        self.assertAlmostEqual(rows[0]["balance_cny"], 88.88, places=2)

        # 同一小时再跑一次：时间戳不同会新增，但房间还是那一个，不会长出第二个房间
        res2 = collect.collect_once(self.cfg, verbose=False, run_alerts=False)
        self.assertTrue(res2.get("ok"))
        self.assertEqual(len(db.list_rooms(self.conn)), 1)

    def test_build_adapter_picks_direct(self):
        a = build_adapter(self.cfg, None, conn=self.conn)
        self.assertIsInstance(a, DirectAdapter)
        self.assertEqual(a.name, "direct")


if __name__ == "__main__":
    unittest.main(verbosity=2)
