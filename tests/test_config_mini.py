"""自带 YAML 子集解析器的测试：没有 PyYAML 的机器上配置必须照样能读。

跑法::

    python -m unittest discover -s tests -v
"""
from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ysp.config import DEFAULTS, _deep_merge, _load_yaml, _mini_yaml  # noqa: E402


class TestMiniYaml(unittest.TestCase):
    def test_inline_comment(self):
        d = _mini_yaml("direct:\n  timeout: 20   # 秒\n  verify_tls: false  # 关\n")
        self.assertEqual(d["direct"]["timeout"], 20)
        self.assertIs(d["direct"]["verify_tls"], False)

    def test_hash_inside_value_kept(self):
        d = _mini_yaml('room:\n  label: 3#楼 502\n  note: "a # b"\n')
        self.assertEqual(d["room"]["label"], "3#楼 502")
        self.assertEqual(d["room"]["note"], "a # b")

    def test_flow_list(self):
        d = _mini_yaml("app:\n  people: 4\n  people_options: [4, 5]\n  names: [a, 'b c']\n")
        self.assertEqual(d["app"]["people_options"], [4, 5])
        self.assertEqual(d["app"]["names"], ["a", "b c"])

    def test_flow_map_in_list(self):
        d = _mini_yaml(
            "vacancy:\n"
            "  periods:\n"
            '    - { from: "2026-07-01", to: "2026-08-31", note: "暑假" }\n')
        self.assertEqual(d["vacancy"]["periods"],
                         [{"from": "2026-07-01", "to": "2026-08-31", "note": "暑假"}])

    def test_block_list_of_maps(self):
        d = _mini_yaml("rooms:\n  - room_key: A-1\n    label: 一号楼\n  - room_key: A-2\n")
        self.assertEqual(len(d["rooms"]), 2)
        self.assertEqual(d["rooms"][0]["room_key"], "A-1")
        self.assertEqual(d["rooms"][1]["room_key"], "A-2")

    def test_example_config_has_direct_section(self):
        text = (ROOT / "config.example.yaml").read_text(encoding="utf-8")
        mini = _mini_yaml(text)
        real = _load_yaml(text)
        for d in (mini, real):
            c = d["direct"]
            self.assertEqual(c["school_code"], "10356")
            self.assertEqual(int(c["session_ttl_minutes"]), 30)
            self.assertEqual(int(c["send_interval_seconds"]), 60)
            self.assertEqual(int(c["phone_daily_limit"]), 6)
            self.assertEqual(int(c["ip_daily_limit"]), 20)
            self.assertEqual(int(c["timeout"]), 20)
            self.assertEqual(c["app_all_version"], "7.3.6")
        self.assertEqual(mini["app"]["people_options"], [4, 5])
        self.assertEqual(mini["app"]["host"], "127.0.0.1")

    def test_defaults_merge_keeps_direct(self):
        cfg = _deep_merge(DEFAULTS, {"direct": {"school_code": "10337"}})
        self.assertEqual(cfg["direct"]["school_code"], "10337")
        self.assertEqual(cfg["direct"]["session_ttl_minutes"], 30)


if __name__ == "__main__":
    unittest.main(verbosity=2)
