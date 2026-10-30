"""直连登录的离线测试：AES / 签名 / 全链路（mock 上游）/ 会话 / 限流。

跑法::

    python -m unittest discover -s tests -v
    python tests/test_direct_login.py          # 等价

不需要网络：上游由本地 mock HTTP 服务模拟。
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ysp import direct_login as D  # noqa: E402

DEV = "ym-57766d45173c643469eadb10a8766666"
DEV2 = "ym-bcbcbb20801444c96978b0c72f114514"
SCHOOL = "10356"

# Go 版 sign_test.go 的官方向量（zjutjh/yxy-go，公开仓库），用来锁死签名算法。
# 里面的手机号 / ymId 是上游公开的测试数据，不是真实用户。
SIGN_VECTORS = [
    ({"appVersion": "730", "sceneCode": "app_user_login", "nt": 1756225768826,
      "deviceId": "ym-57766d45173c643469eadb10a8766666", "platform": "YUNMA_APP",
      "schoolCode": "10337"}, "i85zWFEF0nb8BR8VxQGw7IqkZvT9C5CUqyt6KteO+4U="),
    ({"appVersion": "730", "nt": 1756228132412, "mt": 1756228132115,
      "deviceId": "ym-57766d45173c643469eadb10a8766666", "platform": "YUNMA_APP"},
     "dv2UcggaYmdhK73jlGxZhF4EdvGnR1UW6g8TnZIU7RM="),
    ({"appVersion": "730", "clientId": "65l3attk4r095ib", "appAllVersion": "7.3.6",
      "appPlatform": "Android", "nt": 1756229573789, "mobileType": "23013RK75C",
      "deviceId": "ym-bcbcbb20801444c96978b0c72f114514", "platform": "YUNMA_APP",
      "verificationCode": "123456", "mobilePhone": "13355225522", "osVersion": "15",
      "osType": "Android", "brand": "Redmi", "invitationCode": "", "schoolCode": ""},
     "eR/TDASY3yy8AlHlhqjDRK7/FrVclhp4T2xyyIyq2qI="),
    ({"appVersion": "730", "sceneCode": "app_user_login", "nt": 1756230992802,
      "deviceId": "ym-bcbcbb20801444c96978b0c72f114514", "platform": "YUNMA_APP",
      "schoolCode": ""}, "kXAbBGxdQjpl5kxiYDmVD76nOAbQ7PImqECdy4m7K2k="),
    ({"securityToken": "6d023e2660e76aafd16a7e93c8295bc3aZjutjhwlwCnpH706AwSfQ==",
      "appVersion": "730", "nt": 1756230993220, "deviceId": DEV2,
      "platform": "YUNMA_APP", "schoolCode": ""},
     "ME4fuAlO9zF0I1PanCUdddLbMaVXFOG5unjnw+j3+qo="),
    ({"securityToken": "6d023e2660e76aafd16a7e93c8295bc3aZjutjhwlwCnpH706AwSfQ==",
      "appVersion": "730", "mobilePhone": "13355225522", "nt": 1756231211379,
      "appSecurityToken": "/G/IJOQnR7sjohNq/JFtVhl07BNq797nleNaFfZZDB29HkAhPmDNjGf6wNcA0C3HfZJ12345B84TH3jDC1VDjcUuONlBsk/A15Z1co+buQXOavNWEhwrSJgFDDycYBT5xiGdYB/6EVa7/o5/CJmDLoU1ikYKbrD9EY69juphqq4=",
      "imageCaptchaValue": "y4pm", "sendCount": 1, "deviceId": DEV2,
      "platform": "YUNMA_APP", "schoolCode": ""},
     "KJrBJlLwNZcXXLmHtcHO6LR+tCsxwXUd9yF6ChUmpGU="),
    ({"appVersion": "730", "clientId": "65l3attk4r095ib", "appAllVersion": "7.3.6",
      "appPlatform": "Android", "nt": 1756231286750, "mobileType": "23013RK75C",
      "deviceId": DEV2, "platform": "YUNMA_APP", "verificationCode": "123456",
      "mobilePhone": "13355225522", "osVersion": "15", "osType": "Android",
      "brand": "Redmi", "invitationCode": "", "schoolCode": ""},
     "chMojn114ebG3PR1BmiYz7YLu2AzeING+guiJs7cds8="),
    ({"appVersion": "730", "nt": 1756730606020, "ymId": "2408157831570432666",
      "deviceId": DEV2, "platform": "YUNMA_APP"},
     "9buzHakN0foXRu30s7CyB3B8zH9epcBe5vB+zaBC4s4="),
    ({"appVersion": "730", "clientId": "65l3ben7ub3x6vs", "appAllVersion": "7.3.6",
      "appPlatform": "Android", "nt": 1756734241205, "mobileType": "23013RK75C",
      "deviceId": DEV2, "platform": "YUNMA_APP", "osVersion": "15",
      "ymId": "2408157831570432666", "osType": "Android", "brand": "Redmi",
      "schoolCode": "10337"}, "eDI0hQQ673SN/4m9dTpixTLYpsSm7VgnUtWXXQd5vmw="),
]


class TestAES(unittest.TestCase):
    def test_fips197_vector(self):
        """FIPS-197 附录 B 的标准向量。"""
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plain = bytes.fromhex("00112233445566778899aabbccddeeff")
        rk = D._expand_key(key)
        got = D._encrypt_block(plain, rk)
        self.assertEqual(got.hex(), "69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(D._decrypt_block(got, rk), plain)

    def test_pure_python_matches_cryptography(self):
        """自带实现与 cryptography（若装了）必须逐字节一致。"""
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except Exception:  # noqa: BLE001
            self.skipTest("没装 cryptography，跳过交叉验证")
        key = b"0123456789abcdef"
        data = b"hello-yischool-power"
        enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        expect = enc.update(D._pkcs7_pad(data)) + enc.finalize()
        self.assertEqual(D.aes_ecb_encrypt(data, key), expect)

    def test_pkcs7_roundtrip(self):
        key = b"6d023e2660e76aaf"
        for n in (1, 15, 16, 17, 48):
            data = bytes(range(65, 65 + n))
            self.assertEqual(D.aes_ecb_decrypt(D.aes_ecb_encrypt(data, key), key), data)

    def test_bad_padding(self):
        with self.assertRaises(D.LoginError):
            D.aes_ecb_decrypt(b"\x00" * 16, b"6d023e2660e76aaf")
        with self.assertRaises(D.LoginError):
            D.aes_ecb_decrypt(b"\x00" * 17, b"6d023e2660e76aaf")


class TestSign(unittest.TestCase):
    def test_official_vectors(self):
        for params, want in SIGN_VECTORS:
            self.assertEqual(D.sign(params), want, f"sign({params})")

    def test_skips_empty_strings(self):
        a = D.sign({"appVersion": "730", "deviceId": DEV, "platform": "YUNMA_APP"})
        b = D.sign({"appVersion": "730", "deviceId": DEV, "platform": "YUNMA_APP",
                    "schoolCode": ""})
        self.assertEqual(a, b)

    def test_device_id(self):
        self.assertTrue(D.device_id().startswith("ym-"))
        self.assertEqual(len(D.device_id("AABBCCDD")), 3 + 8)

    def test_mask_phone(self):
        self.assertEqual(D.mask_phone("13800000000"), "138****0000")
        self.assertEqual(D.mask_phone("123"), "")


class TestAppSecurityToken(unittest.TestCase):
    def _make_token(self, t: str = "1a2b3c4d5e6f7g8") -> tuple[str, bytes]:
        key = b"6d023e2660e76aaf"
        cipher = D.aes_ecb_encrypt(t.encode(), key)     # 15 字节 → 16 字节密文
        b64 = base64.b64encode(cipher).decode()         # 24 字符
        tok = key.decode() + "ZjutjhwlwCnpH706" + b64    # 16 + 16 + 24 = 56
        return tok, key

    def test_roundtrip(self):
        tok, key = self._make_token()
        self.assertEqual(len(tok), 56)
        ms = 1756231211379
        ast = D.app_security_token(DEV, tok, ts=ms)
        plain = D.aes_ecb_decrypt(base64.b64decode(ast), key).decode()
        parts = plain.split("|")
        self.assertEqual(parts[:4], [DEV, "YUNMA_APP", "1a2b3c4d5e6f7g8", str(ms)])
        self.assertEqual(parts[4], D.APP_ALL_VERSION)
        want_s = D._md5_upper(D._md5_upper("|".join(parts[:5])))
        self.assertEqual(parts[5], want_s)
        self.assertEqual(len(parts), 6)

    def test_bad_length(self):
        with self.assertRaises(D.LoginError):
            D.app_security_token(DEV, "too-short")


# ------------------------------------------------------------------ mock 上游


class MockUpstream:
    """模拟 compus / auth / application 三个域名，校验签名与加密参数。"""

    def __init__(self):
        self.requests: list[dict] = []
        self.lock = threading.Lock()
        self.require_json_bind = False     # True：queryBind 只接受 JSON（测兜底）
        self.shiro = "fake-shiro-jid-0001"
        self.accept_shiros: set[str] = set()   # 空集合时只认 self.shiro
        self.security_token = ""
        self.captcha_code = "y4pm"
        self.sms_code = "123456"
        self.phone = "13800000000"
        self.uid = "1000000000000000001"
        self.ym_code = "YM-CODE-xyz"
        outer = self

        class H(BaseHTTPRequestHandler):
            server_version = "mock-upstream"

            def log_message(self, *a):  # 静默
                pass

            # -- utils
            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                ctype = (self.headers.get("Content-Type") or "").lower()
                text = raw.decode("utf-8", "replace")
                if "json" in ctype:
                    try:
                        return json.loads(text or "{}"), "json"
                    except ValueError:
                        return {}, "json"
                return {k: v[-1] for k, v in parse_qs(text).items()}, "form"

            def _send(self, obj, status=200, headers=None):
                data = json.dumps(obj, ensure_ascii=False).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for k, v in (headers or []):
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def _rec(self, path, body, ctype):
                with outer.lock:
                    outer.requests.append({"path": path, "body": body,
                                           "ctype": ctype, "headers": dict(self.headers)})

            # -- verbs
            def do_GET(self):
                u = urlparse(self.path)
                q = {k: v[-1] for k, v in parse_qs(u.query).items()}
                self._rec(u.path, q, "query")
                if u.path == "/authoriz/getCodeV2":
                    if q.get("unionid") != outer.uid:
                        self._send({"error": "bad unionid"}, 400)
                        return
                    loc = ("https://application.xiaofubao.com/#/pages/auth/agree"
                           f"?ymCode={outer.ym_code}&state=1")
                    self.send_response(302)
                    self.send_header("Location", loc)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self._send({"statusCode": 1, "message": "not found"}, 404)

            def do_POST(self):
                u = urlparse(self.path)
                body, ctype = self._body()
                self._rec(u.path, body, ctype)
                p = u.path

                if p == "/common/security/token":
                    outer._check_sign(self, body)
                    outer.security_token = outer._make_security_token()
                    self._send({"statusCode": 0, "success": True,
                                "data": {"level": 0,
                                         "securityToken": outer.security_token}})
                    return

                if p == "/common/security/imageCaptcha":
                    if body.get("securityToken") != outer.security_token:
                        self._send({"statusCode": 1, "success": False,
                                    "message": "token无效"})
                        return
                    img = base64.b64encode(b"\x89PNG\r\n\x1a\nfakepng").decode()
                    self._send({"statusCode": 0, "success": True, "data": img})
                    return

                if p == "/compus/user/sendLoginVerificationCode":
                    outer._check_sign(self, body)
                    if body.get("imageCaptchaValue") != outer.captcha_code:
                        self._send({"statusCode": 1, "success": False,
                                    "message": "验证码错误"})
                        return
                    if body.get("mobilePhone") != outer.phone:
                        self._send({"statusCode": 1, "success": False,
                                    "message": "请输入正确的手机号"})
                        return
                    if not outer._check_app_security_token(body):
                        self._send({"statusCode": 1, "success": False,
                                    "message": "encryptedDeviceId不一致"})
                        return
                    self._send({"statusCode": 0, "success": True,
                                "data": {"userExists": True}})
                    return

                if p == "/login/doLoginByVerificationCode":
                    outer._check_sign(self, body)
                    if body.get("verificationCode") != outer.sms_code:
                        self._send({"statusCode": 1, "success": False,
                                    "message": "您已输错1次,3次过后将锁定15分钟,请慎重操作"})
                        return
                    self._send({"statusCode": 0, "success": True,
                                "data": {"id": outer.uid, "bindCardStatus": 1,
                                         "deviceId": body.get("deviceId")}})
                    return

                if p == "/app/login/getUser4Authorize":
                    if body.get("code") != outer.ym_code:
                        self._send({"statusCode": 1, "success": False,
                                    "message": "授权码无效"})
                        return
                    self._send({"statusCode": 0, "success": True, "data": None},
                               headers=[("Set-Cookie", "shiroJID=stale-value; Path=/"),
                                        ("Set-Cookie", f"shiroJID={outer.shiro}; Path=/")])
                    return

                if p == "/app/electric/queryBind":
                    if not self._cookie_ok():
                        self._send({"statusCode": 204, "success": False,
                                    "message": "请重新登录"})
                        return
                    if outer.require_json_bind and ctype != "json":
                        self._send({"statusCode": 999, "success": False,
                                    "message": "系统繁忙"})
                        return
                    self._send({"statusCode": 0, "success": True, "total": 1,
                                "rows": [{"areaId": "1000000000000001",
                                          "buildingCode": "b0001",
                                          "floorCode": "f01",
                                          "roomCode": "0101",
                                          "areaName": "示例校区",
                                          "buildingName": "1 号楼",
                                          "floorName": "1号楼",
                                          "roomName": "0101 室"}]})
                    return

                if p == "/app/electric/queryRoomSurplus":
                    if not self._cookie_ok():
                        self._send({"statusCode": 204, "success": False,
                                    "message": "请重新登录"})
                        return
                    if (body.get("areaId") != "1000000000000001"
                            or body.get("roomCode") != "0101"):
                        self._send({"statusCode": 1, "success": False,
                                    "message": "房间参数错误"})
                        return
                    self._send({"statusCode": 0, "success": True, "data": {
                        "surplus": 123.4, "amount": 88.88,
                        "isShowSurplus": 1, "isShowMoney": 0,
                        "displayRoomName": "示例校区1 号楼01楼0101室"}})
                    return

                self._send({"statusCode": 1, "message": "not found"}, 404)

            def _cookie_ok(self):
                c = self.headers.get("Cookie") or ""
                valid = outer.accept_shiros or {outer.shiro}
                return any(f"shiroJID={s}" in c for s in valid)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    # -- 上游侧辅助
    @staticmethod
    def _make_security_token() -> str:
        key = b"6d023e2660e76aaf"
        cipher = D.aes_ecb_encrypt(b"1a2b3c4d5e6f7g8", key)
        return key.decode() + "ZjutjhwlwCnpH706" + base64.b64encode(cipher).decode()

    def _check_sign(self, handler, body):
        want = D.sign(body)
        if handler.headers.get("sign") != want:
            handler._send({"statusCode": 1, "success": False,
                           "message": "签名校验失败"}, 403)
            raise AssertionError(f"sign 不匹配：{body}")

    def _check_app_security_token(self, body) -> bool:
        try:
            key = body["securityToken"][:16].encode()
            plain = D.aes_ecb_decrypt(base64.b64decode(body["appSecurityToken"]), key)
        except Exception:  # noqa: BLE001
            return False
        return plain.decode().startswith(body["deviceId"] + "|YUNMA_APP|")

    # -- 生命周期
    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"


class TestFlow(unittest.TestCase):
    def _env(self, mock):
        os.environ["YSP_YXY_COMPUS"] = mock.base
        os.environ["YSP_YXY_AUTH"] = mock.base
        os.environ["YSP_YXY_APPLICATION"] = mock.base

    def _clear_env(self):
        for k in ("YSP_YXY_COMPUS", "YSP_YXY_AUTH", "YSP_YXY_APPLICATION"):
            os.environ.pop(k, None)

    def setUp(self):
        self.mock = MockUpstream().__enter__()
        self._env(self.mock)

    def tearDown(self):
        self._clear_env()
        self.mock.__exit__(None, None, None)

    def _login_to_rooms(self) -> tuple[D.DirectLogin, list[dict]]:
        m = self.mock
        cli = D.DirectLogin(dev_id=DEV, school_code=SCHOOL)
        st = cli.security_token()
        self.assertEqual(st["security_token"], m.security_token)
        cap = cli.captcha_image(st["security_token"])
        self.assertTrue(cap["data_uri"].startswith("data:image/png;base64,"))
        self.assertEqual(cli.send_code(m.phone, st["security_token"], m.captcha_code),
                         {"user_exists": True})
        out = cli.login_by_code(m.phone, m.sms_code)
        self.assertEqual(out["uid"], m.uid)
        code = cli.auth_code()
        self.assertEqual(code, m.ym_code)
        self.assertEqual(cli.shiro_jid(code), m.shiro)  # 取最后一个 Set-Cookie
        rooms = cli.query_bind()
        self.assertEqual(len(rooms), 1)
        return cli, rooms

    def test_full_flow_form(self):
        cli, rooms = self._login_to_rooms()
        self.assertEqual(rooms[0]["room_code"], "0101")
        self.assertEqual(rooms[0]["building_code"], "b0001")
        res = cli.query_room_surplus(rooms[0])
        self.assertEqual(res["amount"], 88.88)
        self.assertEqual(res["surplus"], 123.4)
        self.assertIn("0101", res["room_label"])
        self.assertEqual(res["data"]["isShowMoney"], 0)

    def test_query_bind_json_fallback(self):
        """网关只认 JSON 时，自动换格式再试一次并记住。"""
        self.mock.require_json_bind = True
        cli, rooms = self._login_to_rooms()
        self.assertEqual(cli._app_fmt, "json")
        self.assertEqual(rooms[0]["room_code"], "0101")

    def test_wrong_captcha_message(self):
        m = self.mock
        cli = D.DirectLogin(dev_id=DEV, school_code=SCHOOL)
        st = cli.security_token()
        with self.assertRaises(D.LoginError) as cm:
            cli.send_code(m.phone, st["security_token"], "0000")
        self.assertEqual(cm.exception.kind, "captcha")
        self.assertIn("图形验证码", str(cm.exception))

    def test_wrong_sms_code_message(self):
        m = self.mock
        cli = D.DirectLogin(dev_id=DEV, school_code=SCHOOL)
        with self.assertRaises(D.LoginError) as cm:
            cli.login_by_code(m.phone, "999999")
        self.assertEqual(cm.exception.kind, "code")

    def test_error_hint_mapping(self):
        cases = {
            "验证码错误": "captcha",
            "验证码已失效": "captcha",
            "token无效": "token",
            "一分钟内只能发送一次短信,请稍后再试": "limit",
            "短信发送超限，请明天再来": "limit",
            "请重新登录": "expired",
            "学校编码不能为空": "upstream",
        }
        for msg, kind in cases.items():
            with self.assertRaises(D.LoginError) as cm:
                D._unwrap({"statusCode": 1, "success": False, "message": msg})
            self.assertEqual(cm.exception.kind, kind, msg)

    def test_captcha_mime_detection(self):
        # 真实上游给的是 data URI（本次实测是 image/jpeg）
        j = D._normalize_captcha("data:image/jpeg;base64,/9j/AAA")
        self.assertEqual(j["mime"], "image/jpeg")
        self.assertEqual(j["data_uri"], "data:image/jpeg;base64,/9j/AAA")
        self.assertEqual(j["image"], "/9j/AAA")
        # 裸 base64 时按头几个字节认格式，别一律当 png
        png = D._normalize_captcha("iVBORw0KGgoAAAANSUhEUg")
        self.assertEqual(png["mime"], "image/png")
        self.assertTrue(png["data_uri"].startswith("data:image/png;base64,"))
        jpg = D._normalize_captcha("/9j/4AAQSkZJRg")
        self.assertEqual(jpg["mime"], "image/jpeg")
        self.assertEqual(D._normalize_captcha("")["data_uri"], "")

    def test_no_redirect_and_location_parse(self):
        for loc, want in [
            ("https://a.com/#/pages/x?ymCode=abc&state=1", "abc"),
            ("https://a.com/pages/x?ymCode=%E4%B8%AD", "中"),
            ("https://a.com/x#/y?foo=1&ymCode=zzz", "zzz"),
            ("https://a.com/x", ""),
            ("", ""),
        ]:
            self.assertEqual(D._extract_ym_code(loc), want, loc)

    def test_requests_carry_sign_and_no_secret_leak(self):
        cli, rooms = self._login_to_rooms()
        cli.query_room_surplus(rooms[0])
        signed = [r for r in self.mock.requests
                  if r["path"] in ("/common/security/token",
                                   "/compus/user/sendLoginVerificationCode",
                                   "/login/doLoginByVerificationCode")]
        self.assertEqual(len(signed), 3)
        for r in signed:
            self.assertIn("sign", {k.lower() for k in r["headers"]})
            self.assertEqual(r["body"]["deviceId"], DEV)
            self.assertEqual(r["body"]["platform"], "YUNMA_APP")
        # 会话票据只出现在 Cookie 头里，不出现在 body / 返回给前端的数据里
        view = D.DirectSession("sid", DEV, SCHOOL).view()
        self.assertNotIn(self.mock.shiro, json.dumps(view))


class TestSessionsAndLimiter(unittest.TestCase):
    def test_ttl_expiry(self):
        store = D.DirectSessions(ttl=0)
        s = store.create(DEV, SCHOOL)
        time.sleep(0.01)
        with self.assertRaises(D.LoginError) as cm:
            store.get(s.sid)
        self.assertEqual(cm.exception.kind, "expired")

    def test_view_has_no_credentials(self):
        store = D.DirectSessions(ttl=60)
        s = store.create(DEV, SCHOOL)
        s.phone = "13800000000"
        s.client._shiro_jid = "secret-jid"
        s.client.uid = "1000000000000000001"
        s.step = "logged_in"
        view = s.view()
        blob = json.dumps(view, ensure_ascii=False)
        self.assertEqual(view["phone"], "138****0000")
        for secret in ("13800000000", "secret-jid", "1000000000000000001"):
            self.assertNotIn(secret, blob)

    def test_limiter_interval_and_daily(self):
        lim = D.SendLimiter(interval_seconds=60, phone_daily=2, ip_daily=2)
        lim.check("13800000000", "1.1.1.1")
        lim.mark("13800000000", "1.1.1.1")
        with self.assertRaises(D.LoginError) as cm:
            lim.check("13800000000", "1.1.1.1")
        self.assertEqual(cm.exception.kind, "limit")

        lim2 = D.SendLimiter(interval_seconds=0, phone_daily=2, ip_daily=99)
        lim2.mark("13800000000", "")
        lim2.mark("13800000000", "")
        with self.assertRaises(D.LoginError):
            lim2.check("13800000000", "")
        # 另一个号码不受影响
        lim2.check("13900000001", "")

    def test_limiter_ip_cap(self):
        lim = D.SendLimiter(interval_seconds=0, phone_daily=99, ip_daily=1)
        lim.mark("13800000000", "2.2.2.2")
        with self.assertRaises(D.LoginError):
            lim.check("13800000000", "2.2.2.2")

    def test_hour_throttle(self):
        th = D.HourThrottle(per_hour=2)
        for _ in range(2):
            th.check("1.1.1.1")
            th.mark("1.1.1.1")
        with self.assertRaises(D.LoginError) as cm:
            th.check("1.1.1.1")
        self.assertEqual(cm.exception.kind, "limit")
        th.check("2.2.2.2")          # 别的 IP 不受影响
        th.reset()
        th.check("1.1.1.1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
