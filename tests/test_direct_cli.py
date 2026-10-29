"""`python cli.py direct-login` 的离线测试（上游由 mock 模拟）。

跑法::

    python -m unittest discover -s tests -v
"""
from __future__ import annotations

import contextlib
import io
import os
import tempfile
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for p in (str(ROOT), str(Path(__file__).resolve().parent)):
    if p not in sys.path:
        sys.path.insert(0, p)

import cli  # noqa: E402
from test_direct_login import MockUpstream  # noqa: E402


class TestDirectLoginCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mock = MockUpstream().__enter__()
        os.environ["YSP_YXY_COMPUS"] = cls.mock.base
        os.environ["YSP_YXY_AUTH"] = cls.mock.base
        os.environ["YSP_YXY_APPLICATION"] = cls.mock.base
        cls.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)

    @classmethod
    def tearDownClass(cls):
        cls.mock.__exit__(None, None, None)
        for k in ("YSP_YXY_COMPUS", "YSP_YXY_AUTH", "YSP_YXY_APPLICATION"):
            os.environ.pop(k, None)
        cls.tmp.cleanup()

    def setUp(self):
        # 图形验证码落图的位置换成临时目录，别写进真实 data/
        import ysp.config as cfg
        self._root = cfg.ROOT
        cfg.ROOT = Path(self.tmp.name)

    def tearDown(self):
        import ysp.config as cfg
        cfg.ROOT = self._root

    def _run(self, argv: list[str]) -> tuple[int, str]:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.cmd_direct_login(argv)
        return code, buf.getvalue()

    def test_full_run(self):
        code, out = self._run([
            "--phone", self.mock.phone,
            "--captcha", self.mock.captcha_code,
            "--code", self.mock.sms_code,
            "--room", "1",
            "--school", "10356",
        ])
        self.assertEqual(code, 0, out)
        self.assertIn("138****0000", out)
        self.assertIn("88.88", out)
        self.assertIn("123.4", out)
        self.assertIn("isShowMoney=0", out)
        self.assertIn("上游原始响应", out)
        # 凭据不进终端
        for secret in (self.mock.shiro, self.mock.uid, self.mock.phone,
                       self.mock.sms_code, self.mock.security_token):
            self.assertNotIn(secret, out)

    def test_captcha_file_written(self):
        code, _ = self._run(["--phone", self.mock.phone,
                             "--captcha", self.mock.captcha_code,
                             "--code", self.mock.sms_code, "--room", "1"])
        self.assertEqual(code, 0)
        self.assertTrue((Path(self.tmp.name) / "data" / "direct-captcha.png").is_file())

    def test_bad_phone(self):
        code, out = self._run(["--phone", "123", "--captcha", "x", "--code", "1"])
        self.assertEqual(code, 1)
        self.assertIn("11 位", out)

    def test_wrong_captcha(self):
        code, out = self._run(["--phone", self.mock.phone, "--captcha", "0000",
                               "--code", self.mock.sms_code])
        self.assertEqual(code, 1)
        self.assertIn("图形验证码", out)

    def test_wrong_sms_code(self):
        code, out = self._run(["--phone", self.mock.phone,
                               "--captcha", self.mock.captcha_code,
                               "--code", "000000"])
        self.assertEqual(code, 1)
        self.assertIn("登录", out)

    def test_help(self):
        code, out = self._run(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("direct-login", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
