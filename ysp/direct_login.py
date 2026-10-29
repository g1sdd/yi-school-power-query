"""易校园 App 直连登录（不经过 nofish，也不依赖钉钉 H5 抓包）。

用途：**任意用户用自己的手机号 + 自己的短信验证码**登录易校园官方 App 接口，
查到**自己寝室**的电费。全程只用标准库（AES 也自带实现），不需要 pip install。

登录链路（与官方 App 一致，对照公开项目 zjutjh/yxy-go 的协议，未复制其代码）::

    POST compus/common/security/token                     取 securityToken
    POST compus/common/security/imageCaptcha              取图形验证码
    POST compus/compus/user/sendLoginVerificationCode     发短信
    POST compus/login/doLoginByVerificationCode           短信码登录 → ymId(uid)
    GET  auth/authoriz/getCodeV2                          → 302 Location 里的 ymCode
    POST application/app/login/getUser4Authorize          → Set-Cookie: shiroJID
    POST application/app/electric/queryBind               → 已绑定房间列表
    POST application/app/electric/queryRoomSurplus        → 余额

安全边界（硬性）：
  * 短信只发到手机号本人，不支持「输入别人手机号直接查」；
  * 图形验证码必须由人输入，本模块**不做任何 OCR/绕过**；
  * 本模块**不落盘**：不写数据库、不写日志文件；
    `shiroJID` / 短信码 / `ymId` / 完整手机号都不打印、不返回给前端。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

# ------------------------------------------------------------------ 常量
# 这些值来自官方 App 7.3.6 / 730；上游改版时需要改这里（或 config.yaml 的 direct 段）

APP_VERSION = "730"                 # 请求参数 appVersion
APP_ALL_VERSION = "7.3.6"           # 请求参数 appAllVersion + UA
CLIENT_ID = "65l3attk4r095ib"
PLATFORM = "YUNMA_APP"
DEFAULT_SCHOOL_CODE = "10356"       # 中国计量大学
DEFAULT_SCHOOL_NAME = "中国计量大学"
ELECTRICITY_APP_ID = "1810181825222034"   # 电费小程序 ymAppId

COMPUS_BASE = "https://compus.xiaofubao.com"
APPLICATION_BASE = "https://application.xiaofubao.com"
AUTH_BASE = "https://auth.xiaofubao.com"

_UA_TMPL = (
    "Mozilla/5.0 (Linux; Android 12; Android for arm64; wv) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Version/4.0 Chrome/126.0.6478.186 Mobile Safari/537.36 "
    "ZJYXYwebviewbroswer ZJYXYAndroid "
    "tourCustomer/yunmaapp.NET/{ver}/{device}"
)

# 上游错误文案 → 人话。上游 `message` 有时带数字后缀（输错几次），用前缀匹配。
_ERROR_HINTS = (
    ("验证码已失效", "captcha", "图形验证码已失效，请点「换一张」后重新输入"),
    ("验证码错误", "captcha", "图形验证码不对，请重新输入"),
    ("token无效", "token", "登录票据已失效，请点「换一张」重新获取验证码"),
    ("encryptedDeviceId不一致", "device", "设备标识被上游拒绝，请刷新页面重试"),
    ("请输入正确的手机号", "phone", "手机号格式不对"),
    ("手机号格式不正确", "phone", "手机号格式不对"),
    ("一分钟内只能发送一次短信", "limit", "发送太频繁，请 1 分钟后再试"),
    ("短信发送超限，请一分钟后再试", "limit", "发送太频繁，请 1 分钟后再试"),
    ("短信发送超限，请明天再来", "limit", "今天的发送次数已用完，请明天再试"),
    ("您已输错3次,账户被锁定15分钟", "locked", "短信验证码输错 3 次，账户已锁定 15 分钟"),
    ("3次过后将锁定15分钟", "code", "短信验证码不对（再错会锁定 15 分钟）"),
    ("用户不存在", "upstream", "该手机号尚未注册易校园"),
    ("请重新登录", "expired", "登录态已失效，请重新登录"),
    ("学校编码不能为空", "upstream", "学校代码为空：请在 config.yaml 里配置 direct.school_code"),
)


class LoginError(RuntimeError):
    """可预期的登录/查询失败。`kind` 供上层映射成提示和 HTTP 状态码。

    kind: network / upstream / captcha / token / phone / code / limit /
          locked / expired / device / config
    """

    def __init__(self, message: str, kind: str = "upstream"):
        super().__init__(message)
        self.kind = kind


# ================================================================== AES-128-ECB
# securityToken 里那一段必须用 AES-128-ECB 解出来。服务器上不一定有
# cryptography / pycryptodome，装依赖又会破坏「零依赖」这个卖点，所以这里
# 自带一份 AES-128（FIPS-197），并优先用 cryptography（如果装了，只是更快）。


def _rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _gen_sbox() -> list[int]:
    """按 GF(2^8) 求逆 + 仿射变换生成 S 盒（避免手抄 256 个常量出错）。"""
    sbox = [0] * 256
    p = q = 1
    while True:
        p ^= (p << 1) ^ (0x1B if p & 0x80 else 0)
        p &= 0xFF
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        sbox[p] = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4) ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


_SBOX = _gen_sbox()
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _expand_key(key: bytes) -> list[list[int]]:
    if len(key) != 16:
        raise LoginError("AES 密钥必须是 16 字节", "config")
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // 4 - 1]
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [[b for word in w[4 * r:4 * r + 4] for b in word] for r in range(11)]


def _shift_rows(s: list[int]) -> list[int]:
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
    return out


def _inv_shift_rows(s: list[int]) -> list[int]:
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = s[r + 4 * ((c - r) % 4)]
    return out


def _mul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF
        b >>= 1
    return r


def _mix_columns(s: list[int]) -> list[int]:
    out = list(s)
    for c in range(4):
        i = 4 * c
        a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
        out[i] = _mul(a0, 2) ^ _mul(a1, 3) ^ a2 ^ a3
        out[i + 1] = a0 ^ _mul(a1, 2) ^ _mul(a2, 3) ^ a3
        out[i + 2] = a0 ^ a1 ^ _mul(a2, 2) ^ _mul(a3, 3)
        out[i + 3] = _mul(a0, 3) ^ a1 ^ a2 ^ _mul(a3, 2)
    return out


def _inv_mix_columns(s: list[int]) -> list[int]:
    out = list(s)
    for c in range(4):
        i = 4 * c
        a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
        out[i] = _mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9)
        out[i + 1] = _mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13)
        out[i + 2] = _mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11)
        out[i + 3] = _mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14)
    return out


def _encrypt_block(block: bytes, rk: list[list[int]]) -> bytes:
    s = [a ^ b for a, b in zip(block, rk[0])]
    for r in range(1, 10):
        s = [_SBOX[b] for b in s]
        s = _shift_rows(s)
        s = _mix_columns(s)
        s = [a ^ b for a, b in zip(s, rk[r])]
    s = [_SBOX[b] for b in s]
    s = _shift_rows(s)
    s = [a ^ b for a, b in zip(s, rk[10])]
    return bytes(s)


def _decrypt_block(block: bytes, rk: list[list[int]]) -> bytes:
    s = [a ^ b for a, b in zip(block, rk[10])]
    for r in range(9, 0, -1):
        s = _inv_shift_rows(s)
        s = [_INV_SBOX[b] for b in s]
        s = [a ^ b for a, b in zip(s, rk[r])]
        s = _inv_mix_columns(s)
    s = _inv_shift_rows(s)
    s = [_INV_SBOX[b] for b in s]
    return bytes(a ^ b for a, b in zip(s, rk[0]))


def _pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    n = block - len(data) % block
    return data + bytes([n]) * n


def _pkcs7_unpad(data: bytes, block: int = 16) -> bytes:
    if not data or len(data) % block:
        raise LoginError("AES 密文长度不对（不是 16 的整数倍）", "token")
    n = data[-1]
    if not 1 <= n <= block or data[-n:] != bytes([n]) * n:
        raise LoginError("AES 填充校验失败", "token")
    return data[:-n]


def _cryptography_aes() -> Any:
    """装了 cryptography 就用它（快）；没装返回 None，走自带实现。"""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore
    except Exception:  # noqa: BLE001  # ImportError 或环境不完整
        return None
    return Cipher, algorithms, modes


_CIPHER = _cryptography_aes()


def aes_ecb_encrypt(data: bytes, key: bytes) -> bytes:
    """AES-128-ECB 加密 + PKCS7 填充。"""
    if len(key) != 16:
        raise LoginError("AES 密钥必须是 16 字节", "config")
    plain = _pkcs7_pad(data)
    if _CIPHER is not None:
        Cipher, algorithms, modes = _CIPHER
        enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        return enc.update(plain) + enc.finalize()
    rk = _expand_key(key)
    return b"".join(_encrypt_block(plain[i:i + 16], rk) for i in range(0, len(plain), 16))


def aes_ecb_decrypt(data: bytes, key: bytes) -> bytes:
    """AES-128-ECB 解密 + 去 PKCS7 填充。"""
    if len(key) != 16:
        raise LoginError("AES 密钥必须是 16 字节", "config")
    if not data or len(data) % 16:
        raise LoginError("AES 密文长度不对（不是 16 的整数倍）", "token")
    if _CIPHER is not None:
        Cipher, algorithms, modes = _CIPHER
        dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        plain = dec.update(data) + dec.finalize()
    else:
        rk = _expand_key(key)
        plain = b"".join(_decrypt_block(data[i:i + 16], rk) for i in range(0, len(data), 16))
    return _pkcs7_unpad(plain)


# ================================================================== 公共参数 / 签名


def device_id(seed: str = "") -> str:
    """生成 deviceId：`ym-` + 32 位 hex（官方 App 的格式）。"""
    raw = re.sub(r"[^0-9a-fA-F]", "", seed or "") or uuid.uuid4().hex
    return ("ym-" + raw.lower())[:35]


def base_params(dev_id: str, school_code: str = "", nt: int | None = None) -> dict:
    """每个 compus 请求都带的公共参数。"""
    return {
        "appVersion": APP_VERSION,
        "deviceId": dev_id,
        "platform": PLATFORM,
        "schoolCode": str(school_code or ""),
        "nt": int(nt if nt is not None else time.time() * 1000),
    }


def sign(params: dict) -> str:
    """易校园签名。

    1. 参数按 key 字典序排序，非空字符串值用 `|` 连接成 payload；
    2. key = sha256(ymId 后 13 位 + deviceId 后 29 位) 的 hex 后 32 位（登录前没有 ymId，只用 deviceId）；
    3. sign = base64(hmac_sha256(key, payload))。
    """
    keys = sorted(str(k) for k in params)
    values = []
    for k in keys:
        v = params.get(k)
        if isinstance(v, str) and v == "":
            continue
        values.append(str(v))
    payload = "|".join(values)

    builder = ""
    ym = params.get("ymId")
    if isinstance(ym, str) and len(ym) >= 13:
        builder += ym[-13:]
    dev = params.get("deviceId")
    if isinstance(dev, str) and len(dev) >= 29:
        builder += dev[-29:]
    key = hashlib.sha256(builder.encode("utf-8")).hexdigest()[32:].encode("utf-8")

    digest = hmac.new(key, payload.encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def _md5_upper(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest().upper()


def app_security_token(dev_id: str, security_token: str,
                       ts: int | None = None, app_all_version: str = APP_ALL_VERSION) -> str:
    """发短信必须的 appSecurityToken。

    securityToken 长度 56：
      key    = 前 16 个字符
      cipher = base64decode(后 24 个字符) → AES-ECB 解密得到 t
      s      = MD5(MD5(deviceId|YUNMA_APP|t|ts|APP_ALL_VERSION)) 两次，全程大写
      token  = base64(AES-ECB-encrypt(deviceId|YUNMA_APP|t|ts|APP_ALL_VERSION|s))
    """
    tok = str(security_token or "").strip()
    if len(tok) != 56:
        raise LoginError("securityToken 长度不是 56，上游可能已改版", "token")
    key = tok[:16].encode("ascii")
    try:
        cipher = base64.b64decode(tok[32:], validate=False)
    except Exception:  # noqa: BLE001
        raise LoginError("securityToken 不是合法 base64", "token") from None
    t = aes_ecb_decrypt(cipher, key).decode("utf-8", "replace")
    ms = int(ts if ts is not None else time.time() * 1000)
    plain = f"{dev_id}|{PLATFORM}|{t}|{ms}|{app_all_version}"
    s = _md5_upper(_md5_upper(plain))
    return base64.b64encode(
        aes_ecb_encrypt(f"{plain}|{s}".encode("utf-8"), key)
    ).decode("ascii")


# ================================================================== HTTP


@dataclass
class _Resp:
    status: int
    headers: Any = None
    text: str = ""

    def json(self) -> Any:
        try:
            return json.loads(self.text)
        except ValueError:
            raise LoginError(f"上游返回的不是 JSON：{self.text[:160]}", "upstream") from None

    def cookies(self) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        if self.headers is None:
            return out
        for raw in (self.headers.get_all("Set-Cookie") or []):
            pair = raw.split(";", 1)[0]
            k, _, v = pair.partition("=")
            if k.strip():
                out.append((k.strip(), v.strip()))
        return out


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """不自动跟随 302 —— getCodeV2 的 ymCode 就在 Location 里。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def _endpoints() -> dict[str, str]:
    """上游地址（测试/代理可用环境变量改写）。"""
    return {
        "compus": (os.environ.get("YSP_YXY_COMPUS") or COMPUS_BASE).rstrip("/"),
        "application": (os.environ.get("YSP_YXY_APPLICATION") or APPLICATION_BASE).rstrip("/"),
        "auth": (os.environ.get("YSP_YXY_AUTH") or AUTH_BASE).rstrip("/"),
    }


def _request(url: str, method: str = "POST", *, json_body: Any = None,
             form_body: dict | None = None, headers: dict | None = None,
             timeout: int = 20, verify_tls: bool = False,
             allow_redirect: bool = False) -> _Resp:
    data = None
    hdrs = {"Accept": "application/json, text/plain, */*"}
    if headers:
        hdrs.update(headers)
    if json_body is not None:
        data = json.dumps(json_body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json;charset=UTF-8")
    elif form_body is not None:
        data = urllib.parse.urlencode(form_body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method.upper())

    handlers: list[Any] = []
    if not allow_redirect:
        handlers.append(_NoRedirect())
    if not verify_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return _Resp(resp.status, resp.headers,
                         resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        # 302/4xx/5xx：把状态行和 body 原样带回，交给上层判断（可能带业务 JSON）
        try:
            text = e.read().decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            text = ""
        return _Resp(e.code, e.headers, text)
    except urllib.error.URLError as e:
        raise LoginError(f"连不上易校园服务器：{e.reason}", "network") from None
    except (TimeoutError, OSError) as e:
        raise LoginError(f"网络异常：{e}", "network") from None


def _unwrap(payload: Any, what: str = "请求") -> Any:
    """校验上游信封，返回 data。失败抛 LoginError（带人话）。"""
    if not isinstance(payload, dict):
        raise LoginError(f"{what} 返回格式异常", "upstream")
    code = payload.get("statusCode")
    ok = True
    if code is not None and str(code) not in ("0", "200"):
        ok = False
    if payload.get("success") is False:
        ok = False
    if ok:
        return payload.get("data")
    msg = str(payload.get("message") or payload.get("msg") or "").strip()
    if not msg:
        msg = f"{what} 失败（statusCode={code}）"
    kind = "upstream"
    for needle, k, human in _ERROR_HINTS:
        if needle in msg:
            kind, msg = k, human
            break
    raise LoginError(msg, kind)


# base64 前缀 → mime：上游偶尔给裸 base64（不带 data: 前缀），靠头几个字节认格式
_B64_MAGIC = (
    ("iVBORw0KGgo", "image/png"),
    ("/9j/", "image/jpeg"),
    ("R0lGOD", "image/gif"),
    ("UklGR", "image/webp"),
    ("Qk", "image/bmp"),
)


def _normalize_captcha(data: Any) -> dict:
    """图形验证码统一成 {image, mime, data_uri}，前端 <img src=data_uri>。"""
    s = str(data or "").strip()
    if not s:
        return {"image": "", "mime": "", "data_uri": ""}
    if s.startswith("data:"):
        head, _, b64 = s.partition(",")
        mime = (head[5:].split(";")[0] or "image/png").strip()
        return {"image": b64.strip(), "mime": mime, "data_uri": s}
    mime = "image/png"
    for magic, m in _B64_MAGIC:
        if s.startswith(magic):
            mime = m
            break
    return {"image": s, "mime": mime, "data_uri": f"data:{mime};base64,{s}"}


def _extract_ym_code(location: str) -> str:
    """从 302 的 Location 里取 ymCode（上游有时把它放在 `#/` 之后）。"""
    loc = (location or "").strip()
    if not loc:
        return ""
    m = re.search(r"[?&]ymCode=([^&#]+)", loc)
    if m:
        return urllib.parse.unquote(m.group(1))
    plain = loc.replace("#/", "/")
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(plain).query)
    vals = q.get("ymCode") or []
    return vals[0] if vals else ""


def mask_phone(phone: str) -> str:
    p = str(phone or "")
    return f"{p[:3]}****{p[-4:]}" if len(p) == 11 and p.isdigit() else ""


# ================================================================== 落库前的加密
# 「浏览器记住登录」意味着 shiroJID 必须落库。它是真凭据，不能明文躺在 SQLite 里
# （备份/拷给别人的 power.db 会连带泄漏）。这里用 AES-128-CTR + HMAC-SHA256
# 做 encrypt-then-MAC，密钥放 data/direct.key。

def _ctr_xor(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-128-CTR：密钥流 = AES(iv || counter)，逐块异或。"""
    if len(key) != 16:
        raise LoginError("加密密钥必须是 16 字节", "config")
    rk = _expand_key(key)
    out = bytearray()
    counter = 0
    while len(out) < len(data):
        ks = _encrypt_block(iv + counter.to_bytes(8, "big"), rk)
        chunk = data[len(out):len(out) + 16]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
        counter += 1
    return bytes(out)


def _mac_key(key: bytes) -> bytes:
    return hashlib.sha256(key + b"|ysp-mac").digest()[:16]


def seal(plaintext: str, key: bytes) -> str:
    """加密 + 防篡改，返回可存库的 base64url 字符串。"""
    iv = os.urandom(8)
    ct = _ctr_xor(str(plaintext).encode("utf-8"), key, iv)
    tag = hmac.new(_mac_key(key), iv + ct, hashlib.sha256).digest()[:16]
    return base64.urlsafe_b64encode(iv + ct + tag).decode("ascii")


def unseal(blob: str, key: bytes) -> str:
    """解开 seal() 的结果；被改过/密钥不对都直接报错，不返回半截明文。"""
    try:
        raw = base64.urlsafe_b64decode(str(blob or "").encode("ascii"))
    except Exception:  # noqa: BLE001
        raise LoginError("加密数据格式不对", "config") from None
    if len(raw) < 8 + 16:
        raise LoginError("加密数据太短", "config")
    iv, ct, tag = raw[:8], raw[8:-16], raw[-16:]
    want = hmac.new(_mac_key(key), iv + ct, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, want):
        raise LoginError("加密数据校验失败（密钥换了或数据被改过）", "config")
    return _ctr_xor(ct, key, iv).decode("utf-8", "replace")


# ================================================================== 客户端


@dataclass
class DirectLogin:
    """一次登录尝试的全部状态。**不要序列化、不要落盘。**"""

    dev_id: str = ""
    school_code: str = DEFAULT_SCHOOL_CODE
    school_name: str = DEFAULT_SCHOOL_NAME
    timeout: int = 20
    verify_tls: bool = False
    app_all_version: str = APP_ALL_VERSION
    client_id: str = CLIENT_ID
    electricity_app_id: str = ELECTRICITY_APP_ID
    # 运行时
    uid: str = ""                 # 上游返回的 id，作为 getCodeV2 的 unionid
    _shiro_jid: str = ""         # 会话票据：只在内存里，不打印不返回
    _app_fmt: str = "form"       # application 域名的 body 形式：form / json

    # ---------------------------------------------------------- 底层
    def _ua(self) -> str:
        return _UA_TMPL.format(ver=self.app_all_version, device=self.dev_id)

    def _post_compus(self, path: str, params: dict) -> Any:
        """compus 域名的 POST：JSON body + sign 头。"""
        eps = _endpoints()
        body = base_params(self.dev_id, self.school_code)
        body.update({k: v for k, v in params.items() if v is not None})
        headers = {"User-Agent": self._ua(), "sign": sign(body)}
        resp = _request(eps["compus"] + path, "POST", json_body=body,
                        headers=headers, timeout=self.timeout,
                        verify_tls=self.verify_tls)
        return _unwrap(resp.json(), path.rsplit("/", 1)[-1])

    def _post_app(self, path: str, params: dict, shiro_jid: str,
                  fmt: str | None = None, envelope: bool = False) -> Any:
        """application 域名的 POST：带 Cookie: shiroJID。

        `envelope=True` 时返回整个信封（queryBind 的 rows 在顶层，不在 data 里）。
        """
        eps = _endpoints()
        headers = {"User-Agent": self._ua()}
        if shiro_jid:
            headers["Cookie"] = f"shiroJID={shiro_jid}"
        use = fmt or self._app_fmt
        kw = {"json_body": params} if use == "json" else {"form_body": params}
        resp = _request(eps["application"] + path, "POST", headers=headers,
                        timeout=self.timeout, verify_tls=self.verify_tls, **kw)
        if resp.status >= 400 and not resp.text.strip():
            raise LoginError(f"易校园接口 {path} 返回 HTTP {resp.status}", "upstream")
        payload = resp.json()
        _unwrap(payload, path.rsplit("/", 1)[-1])
        return payload if envelope else payload.get("data")

    # ---------------------------------------------------------- 1. 登录票据
    def security_token(self) -> dict:
        """取 securityToken（发短信/取图形码的前提）。"""
        data = self._post_compus("/common/security/token",
                                 {"sceneCode": "app_user_login"})
        data = data if isinstance(data, dict) else {}
        tok = str(data.get("securityToken") or "")
        try:
            level = int(data.get("level") or 0)
        except (TypeError, ValueError):
            level = 0
        if not tok:
            raise LoginError("上游没有返回 securityToken", "token")
        return {"security_token": tok, "level": level}

    # ---------------------------------------------------------- 2. 图形验证码
    def captcha_image(self, security_token: str) -> dict:
        data = self._post_compus("/common/security/imageCaptcha",
                                 {"securityToken": security_token})
        cap = _normalize_captcha(data)
        if not cap["data_uri"]:
            raise LoginError("上游没有返回图形验证码", "captcha")
        return cap

    # ---------------------------------------------------------- 3. 发短信
    def send_code(self, phone: str, security_token: str, captcha: str = "") -> dict:
        phone = str(phone or "").strip()
        if not (len(phone) == 11 and phone.isdigit()):
            raise LoginError("请输入 11 位中国大陆手机号", "phone")
        ast = app_security_token(self.dev_id, security_token,
                                 app_all_version=self.app_all_version)
        params = {
            "securityToken": security_token,
            "mobilePhone": phone,
            "sendCount": 1,
            "appSecurityToken": ast,
        }
        cap = str(captcha or "").strip()
        if cap:
            params["imageCaptchaValue"] = cap
        data = self._post_compus("/compus/user/sendLoginVerificationCode", params)
        out = data if isinstance(data, dict) else {}
        return {"user_exists": bool(out.get("userExists", True))}

    # ---------------------------------------------------------- 4. 短信码登录
    def login_by_code(self, phone: str, sms_code: str) -> dict:
        phone = str(phone or "").strip()
        code = str(sms_code or "").strip()
        if not (len(phone) == 11 and phone.isdigit()):
            raise LoginError("请输入 11 位中国大陆手机号", "phone")
        if not (4 <= len(code) <= 8 and code.isdigit()):
            raise LoginError("请输入短信里的数字验证码", "code")
        data = self._post_compus("/login/doLoginByVerificationCode", {
            "mobilePhone": phone,
            "verificationCode": code,
            "appAllVersion": self.app_all_version,
            "appPlatform": "Android",
            "brand": "Android",
            "clientId": self.client_id,
            "invitationCode": "",
            "mobileType": "Android for arm64",
            "osType": "Android",
            "osVersion": "12",
        })
        out = data if isinstance(data, dict) else {}
        uid = str(out.get("id") or "").strip()
        if not uid:
            raise LoginError("登录成功但上游没返回用户 ID", "upstream")
        self.uid = uid
        return {"uid": uid, "bind_card_status": out.get("bindCardStatus")}

    # ---------------------------------------------------------- 5. ymCode
    def auth_code(self, uid: str = "") -> str:
        """GET auth/authoriz/getCodeV2 → 302 Location 里的 ymCode。"""
        unionid = str(uid or self.uid or "").strip()
        if not unionid:
            raise LoginError("缺少用户 ID，无法换取授权码", "upstream")
        eps = _endpoints()
        query = {
            "bindSkip": "1",
            "authType": "2",
            "ymAppId": self.electricity_app_id,
            "callbackUrl": eps["application"] + "/",
            "unionid": unionid,
            "schoolCode": self.school_code,
            "ymAuthToken": "",
        }
        url = eps["auth"] + "/authoriz/getCodeV2?" + urllib.parse.urlencode(query)
        resp = _request(url, "GET", headers={"User-Agent": self._ua()},
                        timeout=self.timeout, verify_tls=self.verify_tls)
        location = ""
        if resp.headers is not None:
            location = resp.headers.get("Location") or ""
        code = _extract_ym_code(location)
        if not code:
            body = resp.text or ""
            if "用户不存在" in body:
                raise LoginError("该手机号在电费系统里没有账号", "upstream")
            raise LoginError(
                f"没拿到授权码（HTTP {resp.status}，Location={'有' if location else '空'}）。"
                "上游可能改版了。", "upstream")
        return code

    # ---------------------------------------------------------- 6. shiroJID
    @property
    def session_token(self) -> str:
        """当前会话票据（只在内存/加密库里，不打印、不返回前端）。"""
        return self._shiro_jid

    def shiro_jid(self, ym_code: str) -> str:
        eps = _endpoints()
        resp = _request(eps["application"] + "/app/login/getUser4Authorize", "POST",
                        json_body={"authType": "2", "code": ym_code},
                        headers={"User-Agent": self._ua()},
                        timeout=self.timeout, verify_tls=self.verify_tls)
        jar = resp.cookies()
        values = [v for k, v in jar if k.lower() == "shirojid" and v]
        if not values:
            # 顺带把上游的业务错误文案翻出来（不要输出 cookie 内容）
            try:
                _unwrap(resp.json(), "getUser4Authorize")
            except LoginError:
                raise
            except Exception:  # noqa: BLE001
                pass
            raise LoginError("登录成功，但上游没有下发会话票据（shiroJID）", "expired")
        # 上游可能下发多个，取最后一个（官方客户端也这么做）
        self._shiro_jid = values[-1]
        return self._shiro_jid

    # ---------------------------------------------------------- 7. 房间
    def query_bind(self, shiro_jid: str = "") -> list[dict]:
        """已绑定房间列表（MGS 表计，bindType=1）。

        注意：queryBind 的 `rows` 在**响应顶层**，不在 `data` 里。
        """
        token = shiro_jid or self._shiro_jid
        params = {"bindType": "1", "platform": PLATFORM}
        payload: Any = None
        try:
            payload = self._post_app("/app/electric/queryBind", params, token, envelope=True)
        except LoginError as e:
            if e.kind != "upstream":
                raise
            # form / json 互换再试一次：不同学校的网关接受的形式不一样
            alt = "json" if self._app_fmt == "form" else "form"
            try:
                payload = self._post_app("/app/electric/queryBind", params, token,
                                         fmt=alt, envelope=True)
                self._app_fmt = alt
            except LoginError:
                raise e from None

        rows: list = []
        if isinstance(payload, dict):
            if isinstance(payload.get("rows"), list):
                rows = payload["rows"]
            else:
                inner = payload.get("data")
                if isinstance(inner, list):
                    rows = inner
                elif isinstance(inner, dict) and isinstance(inner.get("rows"), list):
                    rows = inner["rows"]
        rooms: list[dict] = []
        for x in rows:
            if not isinstance(x, dict):
                continue
            room = {
                "area_id": str(x.get("areaId") or x.get("areaNo") or ""),
                "building_code": str(x.get("buildingCode") or x.get("buildNo") or ""),
                "floor_code": str(x.get("floorCode") or x.get("floorNo") or ""),
                "room_code": str(x.get("roomCode") or x.get("roomNo") or ""),
                "area_name": str(x.get("areaName") or ""),
                "building_name": str(x.get("buildingName") or x.get("buildName") or ""),
                "floor_name": str(x.get("floorName") or ""),
                "room_name": str(x.get("roomName") or ""),
            }
            if not room["room_code"]:
                continue
            room["label"] = _room_label(room)
            rooms.append(room)
        return rooms

    def query_room_surplus(self, room: dict, shiro_jid: str = "") -> dict:
        """查某个房间的当前余额（MGS：queryRoomSurplus）。"""
        token = shiro_jid or self._shiro_jid
        params = {
            "areaId": str(room.get("area_id") or ""),
            "buildingCode": str(room.get("building_code") or ""),
            "floorCode": str(room.get("floor_code") or ""),
            "roomCode": str(room.get("room_code") or ""),
            "platform": PLATFORM,
        }
        data = self._post_app("/app/electric/queryRoomSurplus", params, token)
        out = data if isinstance(data, dict) else {}
        display = str(out.get("displayRoomName") or "")
        return {
            "room_label": display or _room_label(room),
            "display_room_name": display,
            "amount": _num(out.get("amount")),
            "surplus": _num(out.get("surplus")),
            "is_show_money": _int(out.get("isShowMoney")),
            "is_show_surplus": _int(out.get("isShowSurplus")),
            "data": out,
        }

    # ---------------------------------------------------------- 便捷
    def home_app_id(self, uid: str = "") -> str:
        """从「我的应用」里找电费小程序的 ymAppId（常量失效时的兜底）。"""
        token_uid = str(uid or self.uid or "").strip()
        if not token_uid:
            return ""
        try:
            data = self._post_compus("/compus/application/getHomeAppList", {"ymId": token_uid})
        except LoginError:
            return ""
        items = data if isinstance(data, list) else (
            data.get("appList") if isinstance(data, dict) else None)
        if not isinstance(items, list):
            return ""
        for x in items:
            if not isinstance(x, dict):
                continue
            name = str(x.get("appName") or x.get("name") or "")
            aid = str(x.get("ymAppId") or x.get("appId") or x.get("id") or "")
            if aid and ("电" in name or "electric" in name.lower()):
                return aid
        return ""


def _num(v: Any) -> float | None:
    try:
        return float(v) if v is not None and v != "" else None
    except (TypeError, ValueError):
        return None


def _int(v: Any) -> int | None:
    """上游的开关字段是 0/1，别让它在界面上变成 0.0 / 1.0。"""
    n = _num(v)
    return None if n is None else int(n)


def _room_label(room: dict) -> str:
    """房间展示名：优先上游给的完整名，其次自己拼。"""
    parts = [room.get("area_name"), room.get("building_name"),
             room.get("floor_name"), room.get("room_name")]
    label = "".join(p for p in parts if p).strip()
    if label:
        return label
    if room.get("display_room_name"):
        return str(room["display_room_name"])
    codes = " ".join(str(room.get(k) or "") for k in
                     ("area_id", "building_code", "floor_code", "room_code"))
    return codes.strip() or "我的寝室"


# ================================================================== 内存会话


class DirectSession:
    """一次「一次性查询」的内存会话。**不落库、不写盘。**"""

    def __init__(self, sid: str, dev_id: str, school_code: str,
                 school_name: str = "", ttl: int = 1800):
        self.sid = sid
        self.client = DirectLogin(dev_id=dev_id, school_code=school_code,
                                  school_name=school_name or "")
        self.phone = ""            # 完整手机号只在这里，不返回前端
        self.security_token = ""
        self.captcha_level = 0
        self.captcha_required = True
        self.rooms: list[dict] = []
        self.step = "started"      # started → sent → logged_in
        self.created = time.time()
        self.seen = self.created
        self.ttl = ttl
        self.sends = 0

    # -- 生命周期
    @property
    def expired(self) -> bool:
        return time.time() - self.seen > self.ttl

    def touch(self) -> None:
        self.seen = time.time()

    def expire_at(self) -> str:
        return datetime.fromtimestamp(self.seen + self.ttl).isoformat(timespec="seconds")

    # -- 对外快照（**不含**任何凭据）
    def view(self) -> dict:
        return {
            "session_id": self.sid,
            "phone": mask_phone(self.phone),
            "school_code": self.client.school_code,
            "school_name": self.client.school_name,
            "step": self.step,
            "captcha_required": self.captcha_required,
            "captcha_level": self.captcha_level,
            "sends": self.sends,
            "rooms": [dict(r) for r in self.rooms],
            "expire_at": self.expire_at(),
            "ttl_seconds": self.ttl,
            "logged_in": self.step == "logged_in",
        }


class DirectSessions:
    """进程内会话表：TTL 30 分钟，过期即丢。多进程部署时需要换 Redis。"""

    def __init__(self, ttl: int = 1800, max_sessions: int = 500):
        self.ttl = int(ttl)
        self.max_sessions = int(max_sessions)
        self._d: dict[str, DirectSession] = {}
        self._lock = threading.Lock()

    def create(self, dev_id: str, school_code: str, school_name: str = "") -> DirectSession:
        sid = uuid.uuid4().hex
        s = DirectSession(sid, dev_id, school_code, school_name, ttl=self.ttl)
        with self._lock:
            self.purge_locked()
            if len(self._d) >= self.max_sessions:
                # 满了就丢最老的一个，避免内存无限涨
                oldest = min(self._d.values(), key=lambda x: x.seen)
                self._d.pop(oldest.sid, None)
            self._d[sid] = s
        return s

    def get(self, sid: str) -> DirectSession:
        with self._lock:
            s = self._d.get(str(sid or ""))
            if s is None:
                raise LoginError("会话不存在或已过期，请重新开始", "expired")
            if s.expired:
                self._d.pop(s.sid, None)
                raise LoginError("会话已超过 30 分钟，请重新开始", "expired")
            s.touch()
            return s

    def drop(self, sid: str) -> None:
        with self._lock:
            self._d.pop(str(sid or ""), None)

    def purge_locked(self) -> int:
        dead = [k for k, v in self._d.items() if v.expired]
        for k in dead:
            self._d.pop(k, None)
        return len(dead)

    def purge(self) -> int:
        with self._lock:
            return self.purge_locked()

    def count(self) -> int:
        with self._lock:
            return len(self._d)


class SendLimiter:
    """发短信限流：同一手机号 60 秒一次 + 每日上限；同一 IP 每日上限。

    上游自己也有风控，本地先挡一道，避免把配额烧光和把账号搞进黑名单。
    """

    def __init__(self, interval_seconds: int = 60, phone_daily: int = 6,
                 ip_daily: int = 20):
        self.interval = int(interval_seconds)
        self.phone_daily = int(phone_daily)
        self.ip_daily = int(ip_daily)
        self._phone: dict[str, tuple[float, str, int]] = {}
        self._ip: dict[str, tuple[str, int]] = {}
        self._lock = threading.Lock()

    def check(self, phone: str, ip: str = "") -> None:
        now = time.time()
        today = date.today().isoformat()
        with self._lock:
            last, day, cnt = self._phone.get(phone, (0.0, today, 0))
            if day == today and cnt >= self.phone_daily:
                raise LoginError("今天的发送次数已用完，请明天再试", "limit")
            if last and now - last < self.interval:
                left = int(self.interval - (now - last)) + 1
                raise LoginError(f"发送太频繁，请 {left} 秒后再试", "limit")
            if ip:
                day_ip, cnt_ip = self._ip.get(ip, (today, 0))
                if day_ip == today and cnt_ip >= self.ip_daily:
                    raise LoginError("该网络今天发送次数过多，请明天再试", "limit")

    def mark(self, phone: str, ip: str = "") -> None:
        now = time.time()
        today = date.today().isoformat()
        with self._lock:
            _last, day, cnt = self._phone.get(phone, (0.0, today, 0))
            cnt = cnt + 1 if day == today else 1
            self._phone[phone] = (now, today, cnt)
            if ip:
                day_ip, cnt_ip = self._ip.get(ip, (today, 0))
                cnt_ip = cnt_ip + 1 if day_ip == today else 1
                self._ip[ip] = (today, cnt_ip)


class HourThrottle:
    """滑动窗口限流（默认每小时 N 次）。

    用于 `/direct/start` 这种「不花短信、但每来一次就打两下上游」的接口：
    不拦的话，一个循环刷新的脚本就能把我们的 IP 打进上游风控。
    """

    def __init__(self, per_hour: int = 60, window_seconds: int = 3600):
        self.per_hour = max(1, int(per_hour))
        self.window = int(window_seconds)
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        now = time.time()
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if now - t < self.window]
            self._hits[key] = hits
            if len(hits) >= self.per_hour:
                raise LoginError("请求太频繁，请稍后再试", "limit")

    def mark(self, key: str) -> None:
        now = time.time()
        with self._lock:
            self._hits.setdefault(key, []).append(now)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()
