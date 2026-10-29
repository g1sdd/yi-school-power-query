"""配置加载：优先 config.yaml（若装了 PyYAML），否则回退 config.json。零依赖可用。"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

DEFAULTS: dict[str, Any] = {
    "app": {
        "host": "127.0.0.1",
        "port": 8787,
        "title": "易校园 · 寝室电费监测",
        # 寝室常住人数，用于分摊预估；前端可临时切换
        "people": 4,
        "people_options": [4, 5],
        # serve 启动时自带采集线程（单进程即可 24 小时运行）
        # 关掉就回到「必须另开 python cli.py loop」的老方式
        "auto_collect": True,
        # 日类型：上课日/周末/短假/长假/考试周/寒暑假
        # 节假日从 timor.tech 拉一次后缓存本地，运行时不联网。
        # ⚠️ 现在只打标签，不参与计算 —— 每种日类型样本还太少。
        "daytype": {
            "enabled": True,
            "cache_dir": "data/holidays",
            "term": "2026-2027-1",
            "lookahead_days": 120,      # 往后打多少天的标签
            "lookback_days": 30,        # 往前补多少天
        },
        # 逐小时气温（Open-Meteo，免费无 key）。现在只存不参与计算。
        "weather": {
            "enabled": True,
            "latitude": 30.27,          # 杭州
            "longitude": 120.16,
            "timezone": "Asia/Shanghai",
            "past_days": 14,            # 每次拉取回看多少天（上限 92）
            "forecast_days": 16,        # 往后取多少天（上限 16）
        },
        # 每日自动备份：上游只保留 7 天历史，本地库是唯一的长历史来源
        "backup": {
            "enabled": True,
            "keep": 30,          # 保留最近 30 份
            "dir": "data/backup",
        },
    },
    "db": {"path": "data/power.db"},
    "source": {
        # nofish   : 本项目自带验证码登录（推荐，无需抓包）
        # xiaofubao: 直连易校园上游（需要 shiroJID + ymId，需抓包）
        # demo     : 生成演示数据，无需任何凭据
        "type": "demo",
        "base_url": "https://tool.no-fish.cn",
        "phone": "",
        # 单一学校：登录时选一次，之后固定
        "school_code": "",
        "school_name": "",
        "shiro_jid": "",
        "ym_id": "",
        "timeout": 20,
        # 上游证书过期/代理中间人时自动降级；设 true 则强制校验并直接报错
        "strict_tls": False,
    },
    "rooms": [
        # room_key 用于去重；label 用于展示
        {
            "room_key": "DEMO-3-502",
            "label": "3号楼 502",
            "school_code": "",
            "area_id": "",
            "building_code": "",
            "floor_code": "",
            "room_code": "",
            "unit_price": 0.538,
            "warn_kwh": 20.0,
            "critical_kwh": 5.0,
        }
    ],
    # 直连查询（/direct）：任意用户用本人手机号 + 本人短信验证码
    # 登录易校园官方 App 接口，查自己的电费。支持多用户：各账号互不影响。
    "direct": {
        "enabled": True,
        # 默认学校：中国计量大学。页面上可以改。
        "school_code": "10356",
        "school_name": "中国计量大学",
        # 登录过程（验证码→短信→登录）的一次性会话，只在内存里
        "session_ttl_minutes": 30,
        "max_sessions": 500,
        # 浏览器记住登录多少天；shiroJID 加密存本机库
        "persist_days": 30,
        # 发短信限流（上游自己也有风控，本地先拦一道）
        "send_interval_seconds": 60,
        "phone_daily_limit": 6,
        "ip_daily_limit": 20,
        # /direct/start 每 IP 每小时上限（每次会打两下上游，别让人刷）
        "start_hourly_limit": 60,
        "timeout": 20,
        # 上游证书异常时是否严格校验；默认关（与 source.strict_tls 一致的做法）
        "verify_tls": False,
        # 上游版本号：易校园改版时需要跟着改
        "app_all_version": "7.3.6",
        "client_id": "65l3attk4r095ib",
    },
    "collect": {
        # 易校园每小时更新一次电费，所以默认按小时采集
        "interval_minutes": 60,
        # 整点后延迟几分钟再采，确保上游已经更新完
        "minute_offset": 5,
        # 每次采集的随机抖动（秒），避免固定时刻打上游
        "jitter_seconds": 90,
        "min_gap_seconds": 300,
        # 采集失败重试
        "retry": 3,
        "retry_delay_seconds": 20,
    },
    # 空置期：放假/实习期间宿舍没人，那几天的消耗不该算进日均
    "vacancy": {
        "auto": True,          # 自动识别
        "ratio": 0.25,         # 低到本寝室中位数的 25% 以下
        "min_days": 4,         # 连续至少几天
        # 手动指定（最可靠，你清楚自己什么时候不在）
        # periods:
        #   - { from: "2026-07-01", to: "2026-08-31", note: "暑假" }
        "periods": [],
    },
    "alerts": {
        "enabled": True,
        "webhook_url": "",
        "dedupe_hours": 12,
        # ---- 邮件（SMTP）----
        "email": {
            "enabled": False,
            "smtp_host": "smtp.qq.com",      # QQ邮箱 smtp.qq.com / 163 smtp.163.com / Gmail smtp.gmail.com
            "smtp_port": 465,                # 465=SSL(推荐)  587=STARTTLS  25=明文
            "use_ssl": True,
            "username": "",                  # 完整邮箱地址
            "password": "",                  # 注意：是「授权码」，不是登录密码
            "from_addr": "",                 # 留空则用 username
            "to_addrs": [],                  # 收件人，可多个
            "subject_prefix": "[寝室电费]",
        },
        # ---- 各类告警开关与阈值 ----
        "rules": {
            "low_balance": True,             # 余额低于 room.warn_kwh / critical_kwh
            "spike": True,                   # 单日消耗异常偏高（MAD）
            "stale": True,                   # 数据卡住（余额长时间完全不变）
            "stale_hours": 12,               # 连续多少小时一分钱没动就报
            "session_expired": True,         # 登录会话过期，需要重新验证码登录
            "collect_failed": True,          # 连续采集失败
            "collect_failed_times": 3,       # 连续失败几次后报警
            "forecast_days": 7,              # 预计 N 天内耗尽就提前预警
        },
    },
}


def _deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _load_yaml(text: str) -> dict:
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text) or {}
    except ImportError:
        pass
    # 极简 YAML 子集解析（足够覆盖本项目的配置结构）
    return _mini_yaml(text)


def _mini_yaml(text: str) -> dict:
    """支持 2/4 空格缩进、key: value、- 列表项、# 注释、引号字符串。"""
    root: dict[str, Any] = {}
    stack: list[tuple[int, Any]] = [(-1, root)]
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if line.startswith("- "):
            item = line[2:].strip()
            if isinstance(parent, list):
                if item.startswith("{"):
                    # 行内写法：- { from: "2026-07-01", to: "2026-08-31" }
                    parent.append(_coerce(item))
                elif ":" in item:
                    k, _, v = item.partition(":")
                    d = {k.strip(): _coerce(v.strip())}
                    parent.append(d)
                    stack.append((indent, d))
                else:
                    parent.append(_coerce(item))
            continue
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip(), val.strip()
        if val == "":
            nxt = _peek_child(text, raw)
            container: Any = [] if nxt else {}
            parent[key] = container
            stack.append((indent, container))
        else:
            parent[key] = _coerce(val)
    return root


def _peek_child(text: str, raw: str) -> bool:
    lines = text.splitlines()
    try:
        i = lines.index(raw)
    except ValueError:
        return False
    for nxt in lines[i + 1 :]:
        if not nxt.strip() or nxt.lstrip().startswith("#"):
            continue
        return nxt.strip().startswith("- ")
    return False


def _strip_comment(val: str) -> str:
    """去掉行尾注释。YAML 规则：只有「空白 + #」才是注释起点。

    这样 `label: 3#楼 502` 里的 # 不会被当成注释，
    而 `send_interval_seconds: 60   # 同一手机号...` 能正确得到 60。
    """
    out: list[str] = []
    quote = ""
    for ch in val:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
            out.append(ch)
        elif ch == "#" and out and out[-1] in " \t":
            break
        else:
            out.append(ch)
    return "".join(out).strip()


def _split_flow(text: str) -> list[str]:
    """按逗号切分行内写法，引号里的逗号不算。"""
    parts: list[str] = []
    buf: list[str] = []
    quote = ""
    for ch in text:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
            buf.append(ch)
        elif ch == ",":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf))
    return parts


def _coerce(v: str) -> Any:
    v = _strip_comment(v)
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    # 行内写法：[4, 5] / { from: "2026-07-01", note: "暑假" }
    if len(v) >= 2 and v[0] == "[" and v[-1] == "]":
        inner = v[1:-1].strip()
        return [_coerce(x) for x in _split_flow(inner)] if inner else []
    if len(v) >= 2 and v[0] == "{" and v[-1] == "}":
        inner = v[1:-1].strip()
        out: dict[str, Any] = {}
        if inner:
            for part in _split_flow(inner):
                k, _, val = part.partition(":")
                if k.strip():
                    out[k.strip().strip("\"'")] = _coerce(val)
        return out
    low = v.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "none", "~"):
        return None
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass
    return v


def load_config(path: str | os.PathLike | None = None) -> dict:
    """加载配置，未提供路径时按 config.yaml -> config.json -> 默认值 顺序探测。"""
    candidates: list[Path] = []
    if path:
        candidates.append(Path(path))
    else:
        env = os.environ.get("YSP_CONFIG")
        if env:
            candidates.append(Path(env))
        candidates += [ROOT / "config.yaml", ROOT / "config.yml", ROOT / "config.json"]

    for c in candidates:
        if not c.is_file():
            continue
        text = c.read_text(encoding="utf-8")
        data = _load_yaml(text) if c.suffix in (".yaml", ".yml") else json.loads(text)
        cfg = _deep_merge(DEFAULTS, data or {})
        cfg["_config_path"] = str(c)
        return cfg

    cfg = dict(DEFAULTS)
    cfg["_config_path"] = "(defaults)"
    return cfg


def db_path(cfg: dict) -> Path:
    p = Path(cfg["db"]["path"])
    if not p.is_absolute():
        p = ROOT / p
    p.parent.mkdir(parents=True, exist_ok=True)
    return p
