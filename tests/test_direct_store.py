"""多用户存储层测试：账号 / 浏览器令牌 / 房间 / 加密落库。

跑法::

    python -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ysp import direct_login as dl  # noqa: E402
from ysp import direct_store as st  # noqa: E402

ROOM_A = {"area_id": "1", "building_code": "b", "floor_code": "f",
          "room_code": "0101", "label": "一号楼 0101"}
ROOM_B = {"area_id": "2", "building_code": "c", "floor_code": "g",
          "room_code": "0101", "label": "二号楼 0101"}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.conn = sqlite3.connect(str(Path(self.tmp.name) / "t.db"))
        self.conn.row_factory = sqlite3.Row
        self._key = st.key_path()
        st.set_key_path(Path(self.tmp.name) / "direct.key")

    def tearDown(self):
        self.conn.close()
        st.set_key_path(self._key)
        self.tmp.cleanup()


class TestUsers(Base):
    def test_upsert_is_idempotent(self):
        a = st.upsert_user(self.conn, "13300000001", "10356", "中国计量大学", "uid-1")
        b = st.upsert_user(self.conn, "13300000001", "10356", "中国计量大学", "uid-1")
        self.assertEqual(a["id"], b["id"])
        self.assertEqual(st.stats(self.conn)["users"], 1)

    def test_two_phones_two_users(self):
        a = st.upsert_user(self.conn, "13300000001", "10356")
        b = st.upsert_user(self.conn, "13300000002", "10356")
        self.assertNotEqual(a["id"], b["id"])
        self.assertEqual(st.get_user_by_phone(self.conn, "13300000002")["id"], b["id"])

    def test_public_user_masks_phone_and_hides_uid(self):
        u = st.upsert_user(self.conn, "13300000001", "10356", "中国计量大学", "uid-1")
        pub = st.public_user(u)
        self.assertEqual(pub["phone"], "133****0001")
        blob = json.dumps(pub, ensure_ascii=False)
        self.assertNotIn("13300000001", blob)
        self.assertNotIn("uid-1", blob)


class TestSessions(Base):
    def _login(self, phone="13300000001", shiro="shiro-abc"):
        u = st.upsert_user(self.conn, phone, "10356", "中国计量大学", "uid")
        token, row = st.create_session(self.conn, u["id"], shiro, days=30, ip="1.2.3.4")
        return u, token, row

    def test_token_is_hashed(self):
        _u, token, row = self._login()
        self.assertNotIn(token, json.dumps(row, ensure_ascii=False))
        self.assertEqual(row["token_hash"], st.hash_token(token))
        raw = self.conn.execute("SELECT token_hash FROM dsessions").fetchone()[0]
        self.assertEqual(raw, st.hash_token(token))
        self.assertEqual(len(token), 43)      # token_urlsafe(32)

    def test_get_session_joins_user(self):
        _u, token, _row = self._login()
        row = st.get_session(self.conn, st.hash_token(token))
        self.assertEqual(row["phone"], "13300000001")
        self.assertEqual(row["school_name"], "中国计量大学")

    def test_shiro_is_encrypted_at_rest(self):
        _u, token, _row = self._login(shiro="very-secret-shiro")
        th = st.hash_token(token)
        blob = self.conn.execute("SELECT shiro_sealed FROM dsessions WHERE token_hash=?",
                                 (th,)).fetchone()[0]
        self.assertNotIn("very-secret-shiro", blob)
        row = st.get_session(self.conn, th)
        self.assertEqual(st.get_shiro(self.conn, row), "very-secret-shiro")

    def test_wrong_key_cannot_decrypt(self):
        _u, token, _row = self._login(shiro="very-secret-shiro")
        th = st.hash_token(token)
        row = st.get_session(self.conn, th)
        st.set_key_path(Path(self.tmp.name) / "another.key")   # 换一把钥匙
        self.assertEqual(st.get_shiro(self.conn, row), "")     # 解不开就当没有，不崩

    def test_expiry(self):
        u = st.upsert_user(self.conn, "13300000001", "10356")
        token, _ = st.create_session(self.conn, u["id"], "", days=0)
        self.assertIsNone(st.get_session(self.conn, st.hash_token(token)))
        # 过期的会被删掉
        n = self.conn.execute("SELECT COUNT(*) FROM dsessions").fetchone()[0]
        self.assertEqual(n, 0)

    def test_two_users_two_tokens(self):
        _ua, ta, _ = self._login("13300000001", "shiro-a")
        _ub, tb, _ = self._login("13300000002", "shiro-b")
        ra = st.get_session(self.conn, st.hash_token(ta))
        rb = st.get_session(self.conn, st.hash_token(tb))
        self.assertNotEqual(ra["user_id"], rb["user_id"])
        self.assertEqual(st.get_shiro(self.conn, ra), "shiro-a")
        self.assertEqual(st.get_shiro(self.conn, rb), "shiro-b")

    def test_touch_extends(self):
        _u, token, row = self._login()
        th = st.hash_token(token)
        st.touch_session(self.conn, th, days=30)
        again = st.get_session(self.conn, th)
        self.assertGreaterEqual(again["expires_at"], row["expires_at"])

    def test_delete_and_purge(self):
        _u, token, _ = self._login()
        st.delete_session(self.conn, st.hash_token(token))
        self.assertIsNone(st.get_session(self.conn, st.hash_token(token)))
        self.assertEqual(st.purge(self.conn), 0)

    def test_set_shiro_again(self):
        _u, token, _ = self._login(shiro="old")
        th = st.hash_token(token)
        st.set_shiro(self.conn, th, "new")
        row = st.get_session(self.conn, th)
        self.assertEqual(st.get_shiro(self.conn, row), "new")
        st.set_shiro(self.conn, th, "")
        row = st.get_session(self.conn, th)
        self.assertEqual(st.get_shiro(self.conn, row), "")


class TestRooms(Base):
    def test_save_and_list(self):
        u = st.upsert_user(self.conn, "13300000001", "10356")
        rooms = st.save_rooms(self.conn, u["id"], [ROOM_A, ROOM_B])
        self.assertEqual([r["room_code"] for r in rooms], ["0101", "0101"])
        self.assertEqual(rooms[0]["label"], "一号楼 0101")

    def test_no_duplicates_on_relogin(self):
        u = st.upsert_user(self.conn, "13300000001", "10356")
        st.save_rooms(self.conn, u["id"], [ROOM_A])
        st.save_rooms(self.conn, u["id"], [ROOM_A])
        self.assertEqual(len(st.list_rooms(self.conn, u["id"])), 1)

    def test_unbound_room_removed(self):
        u = st.upsert_user(self.conn, "13300000001", "10356")
        st.save_rooms(self.conn, u["id"], [ROOM_A, ROOM_B])
        st.save_rooms(self.conn, u["id"], [ROOM_A])
        self.assertEqual([r["room_code"] for r in st.list_rooms(self.conn, u["id"])], ["0101"])

    def test_balance_saved(self):
        u = st.upsert_user(self.conn, "13300000001", "10356")
        rooms = st.save_rooms(self.conn, u["id"], [ROOM_A])
        st.update_balance(self.conn, rooms[0]["id"], 88.88, 123.4)
        again = st.list_rooms(self.conn, u["id"])[0]
        self.assertEqual(again["last_amount"], 88.88)
        self.assertEqual(again["last_surplus"], 123.4)
        self.assertTrue(again["last_query_at"])

    def test_users_do_not_share_rooms(self):
        a = st.upsert_user(self.conn, "13300000001", "10356")
        b = st.upsert_user(self.conn, "13300000002", "10356")
        st.save_rooms(self.conn, a["id"], [ROOM_A])
        st.save_rooms(self.conn, b["id"], [ROOM_B])
        self.assertEqual(st.list_rooms(self.conn, a["id"])[0]["room_code"], "0101")
        self.assertEqual(st.list_rooms(self.conn, b["id"])[0]["room_code"], "0101")


class TestKeyFile(Base):
    def test_key_created_and_stable(self):
        k1 = st.secret_key()
        self.assertEqual(len(k1), 16)
        self.assertTrue(st.key_path().is_file())
        self.assertEqual(st.secret_key(), k1)

    def test_seal_roundtrip(self):
        k = st.secret_key()
        blob = dl.seal("hello", k)
        self.assertEqual(dl.unseal(blob, k), "hello")
        self.assertNotIn("hello", blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
