# `/direct` 多人查电费 — 实现说明

> 生成时间：2026-10-29（Asia/Shanghai）
> 目标：**任意用户用本人手机号登录易校园官方 App 接口，查本人寝室电费**。
> 不经过 `tool.no-fish.cn`，也不依赖钉钉 H5 抓包。
> 2026-10-29 晚更新：支持多用户（各账号独立）+ 浏览器持久登录（30 天）+ 内置学校列表。

---

## 1. 它是什么 / 不是什么

| | 模式 A（现有 nofish 采集） | **模式 D（本功能 `/direct`）** |
|---|---|---|
| 给谁用 | 自己 / 室友，长期盯一个房间 | **任意手机号本人**，各查各的 |
| 凭据来源 | 本项目后端替你登录 nofish | 本项目直接调易校园官方 App 接口 |
| 登录态 | SQLite `meta.session`，重启免登 | 每个手机号一个账号，浏览器记住 30 天 |
| 数据 | 小时级历史 + 分析 + 告警 | 当前余额（房间 + 上次查到的数） |
| 图形验证码 | nofish 内部处理 | 人眼看图输入，不做 OCR |

**多用户隔离**（本次新增，见第 6 节）：

- 每个手机号一行 `dusers`，房间在 `drooms`，浏览器令牌在 `dsessions`；
- 三个新表都是 `d` 前缀，**完全不碰** `rooms` / `readings` / `meta.session`；
- 所以：别人在这个页面登录，不会覆盖本站主人的 nofish 登录，也不会看到他的房间。

**不做**：历史曲线、按用户的定时采集、告警、配额。要做这些见
需要另外设计每用户采集与配额。

---

## 2. 登录链路（与官方 App 一致）

```
① POST https://compus.xiaofubao.com/common/security/token
      取 securityToken（+ level，风险等级）
② POST https://compus.xiaofubao.com/common/security/imageCaptcha
      取图形验证码（base64 图片）
③ POST https://compus.xiaofubao.com/compus/user/sendLoginVerificationCode
      发短信（带 appSecurityToken + imageCaptchaValue）
④ POST https://compus.xiaofubao.com/login/doLoginByVerificationCode
      短信码登录 → data.id（= ymId / unionid）
⑤ GET  https://auth.xiaofubao.com/authoriz/getCodeV2
      取 302 的 Location 里的 ymCode（禁止自动跟随重定向）
⑥ POST https://application.xiaofubao.com/app/login/getUser4Authorize
      Set-Cookie: shiroJID（可能有多个，取最后一个）
⑦ POST https://application.xiaofubao.com/app/electric/queryBind
      已绑定房间列表（rows 在**响应顶层**，不在 data 里）
⑧ POST https://application.xiaofubao.com/app/electric/queryRoomSurplus
      body: areaId / buildingCode / floorCode / roomCode / platform
```

公共参数（`compus` 的每个请求都带）：

```text
appVersion = 730          platform = YUNMA_APP
deviceId   = "ym-" + uuid4().hex
schoolCode = 10356        nt = 毫秒时间戳
```

UA（`base.go` 同款，注意末尾带 deviceId）：

```text
Mozilla/5.0 (Linux; Android 12; Android for arm64; wv) AppleWebKit/537.36
(KHTML, like Gecko) Version/4.0 Chrome/126.0.6478.186 Mobile Safari/537.36
ZJYXYwebviewbroswer ZJYXYAndroid
tourCustomer/yunmaapp.NET/7.3.6/<deviceId>
```

响应信封统一是 `{"statusCode":0,"success":true,"data":...}`；
`statusCode != 0` 或 `success:false` 就是失败，**HTTP 也可能仍是 200**。

---

## 3. 签名与 AES

### 3.1 `sign`（只给 `compus.xiaofubao.com` 加，放在 HTTP 头 `sign`）

```text
payload = "|".join(str(v) for k, v in sorted(params) if not (isinstance(v, str) and v == ""))
key     = sha256(last13(ymId) + last29(deviceId)).hexdigest()[32:]   # 登录前没有 ymId
sign    = base64(hmac_sha256(key, payload))
```

- 空字符串跳过；数字按十进制字符串参与（`sendCount: 1` → `"1"`）。
- 用 8 组官方向量做过回归（见 `tests/test_direct_login.py` 的 `SIGN_VECTORS`）。

### 3.2 `appSecurityToken`（发短信必需）

```text
securityToken 长度 56：
  key    = securityToken[:16]
  t      = AES-128-ECB-decrypt(base64decode(securityToken[32:]), key, PKCS7)
  ts     = 当前毫秒
  s      = MD5(MD5(f"{deviceId}|YUNMA_APP|{t}|{ts}|7.3.6").hexdigest().upper()).hexdigest().upper()
  token  = base64(AES-128-ECB-encrypt(f"{deviceId}|YUNMA_APP|{t}|{ts}|7.3.6|{s}", key, PKCS7))
```

**AES 用自带实现**（`ysp/direct_login.py` 里的 `_SBOX` / `_expand_key` / `_encrypt_block`）：

- 纯标准库，`pip install cryptography` 都不需要 —— 服务器上没装也能跑；
- 装了 `cryptography` 会自动用它（更快），两条路径逐字节一致（有交叉测试）；
- 自带实现用 FIPS-197 附录 B 的标准向量校验过。

> 这就是「零第三方依赖」在密码学上的代价：多写了 ~120 行 AES。换来的是
> 部署时不用 pip、不用 openssl、不会被 `ModuleNotFoundError` 打断。

---

## 4. 代码结构

| 文件 | 职责 |
|---|---|
| `ysp/direct_login.py` | 协议客户端：AES、`sign()`、`app_security_token()`、7 步登录、`query_bind()`、`query_room_surplus()`、内存会话 `DirectSessions`、限流 `SendLimiter` |
| `ysp/server.py` | `/api/direct/{start,captcha,send-code,login,query,status,close}` + `LoginError → 400/429` 映射 |
| `web/direct.html` | 手机端三步向导：① 手机号+图形码 ② 短信码 ③ 选房间+余额+原始 JSON |
| `cli.py` | `python cli.py direct-login ...` 终端跑通同一条链路 |
| `tests/test_direct_login.py` | AES / 签名 / 全链路（mock 上游）/ 会话 / 限流 |
| `tests/test_direct_api.py` | `/api/direct/*` 接口（起真实 Handler + mock 上游） |

主要函数：

```python
device_id()                      # "ym-" + 32 hex
base_params(dev, school, nt)     # 公共参数
sign(params)                     # HMAC 签名
aes_ecb_encrypt/decrypt()        # AES-128-ECB + PKCS7
seal(text, key) / unseal(...)    # AES-128-CTR + HMAC，落库前加密
app_security_token(dev, token)   # 发短信用的加密串
DirectLogin.security_token()     # ①
DirectLogin.captcha_image(tok)   # ②
DirectLogin.send_code(...)       # ③
DirectLogin.login_by_code(...)   # ④ → uid
DirectLogin.auth_code(uid)       # ⑤ → ymCode
DirectLogin.shiro_jid(code)      # ⑥ → shiroJID（不打印、不返回前端）
DirectLogin.query_bind()         # ⑦ → rooms
DirectLogin.query_room_surplus(room)   # ⑧ → amount / surplus / raw
```

`ysp/direct_store.py`（多用户）：

```python
ensure(conn)                     # 建 dusers / dsessions / drooms（幂等）
upsert_user(...)                 # 手机号 → 账号（重复登录不重复建）
public_user(user)                # 给前端：手机号打码，不含 ym_id
create_session(conn, uid, shiro) # 发浏览器令牌（库里只存 sha256），shiro 加密存
get_session / touch_session / delete_session / purge
save_rooms / list_rooms / update_balance
secret_key()                     # data/direct.key，首次自动生成
```

`ysp/direct_schools.py`：内置 50 所学校（名称 ↔ 代码），支持按名称/代码筛选。
学校代码**不是纯数字**（`yunma`、`qt036`、`3302200`），别用 `isdigit()` 判断。

---

## 5. 接口

| 方法 | 路径 | 入参 | 返回 |
|---|---|---|---|
| GET | `/api/direct/schools` | `?q=` | `schools[{code,name}]`、`default` |
| POST | `/api/direct/start` | `school?`（名称或代码） | `session_id`、`captcha{data_uri}`、`captcha_required` |
| POST | `/api/direct/captcha` | `session_id` | 新 `captcha` |
| POST | `/api/direct/send-code` | `session_id`、`phone`、`captcha` | `step=sent`、`message`（手机号打码） |
| POST | `/api/direct/login` | `session_id`、`sms_code` | `token`、`user{phone,school}`、`rooms[]` |
| POST | `/api/direct/query` | `room_index` + 令牌 | `balance{amount,surplus}`、`room`、`raw` |
| GET | `/api/direct/session` | 令牌 | `user`、`rooms`、`has_login` |
| GET | `/api/direct/me` | 令牌 | 当前用户自己的寝室与最近余额 |
| POST | `/api/direct/logout` | 令牌 | `{ok:true}`，同时清 Cookie |
| POST | `/api/direct/adopt` | `token` | 把旧 localStorage 令牌换成 Cookie |
| GET | `/api/direct/status` | `session_id` | 登录过程快照 |
| POST | `/api/direct/close` | `session_id` | 丢掉一次性会话 |

登录成功后服务端下发 **httpOnly Cookie** `ysp_session`（30 天），浏览器自己带着，
JS 读不到；接口也接受请求头 `X-YS-Token` 或 body 里的 `token`（给脚本/CLI 用），
**不放 URL** —— 免得进访问日志。

失败统一返回 `{"error": "人话", "kind": "captcha|token|phone|code|limit|expired|relogin|...", "direct": true}`，
`kind=limit` 用 HTTP 429，其余 400。

**房间只能用序号**（`room_index` 必须落在该账号自己的房间列表里），不接受前端传
`areaId/roomCode` —— 否则等于开放「拿着你的令牌查别人房间余额」。

`kind=relogin` 表示上游把 `shiroJID` 作废了（页面上就是「登录已失效，重新验证一下手机号」）。
此时令牌和房间都还在，只是需要再收一次短信。

---

## 6. 多用户与持久登录

### 6.1 表结构（全部 `d` 前缀，和单用户采集隔离）

| 表 | 一行是 | 关键列 |
|---|---|---|
| `dusers` | 一个手机号账号 | `phone`（唯一）、`school_code`、`school_name`、`ym_id` |
| `dsessions` | 一个浏览器 | `token_hash`（sha256）、`user_id`、`shiro_sealed`（加密）、`expires_at` |
| `drooms` | 一个寝室 | `user_id`、`area/building/floor/room_code`、`label`、`last_amount`、`last_surplus` |

- 令牌是 `secrets.token_urlsafe(32)`，**库里只存 sha256**，原文只在浏览器的 httpOnly Cookie 里。
- `shiroJID` 用 AES-128-CTR + HMAC-SHA256 加密后存（密钥 `data/direct.key`，16 字节，`chmod 600`）。
  密钥丢了 = 所有已存登录失效，重新收一次短信即可，不会崩。
- 同一手机号在别的设备再登录会新建一个 `dsessions` 行，旧设备各自持有自己的票据。

### 6.2 「不会互相覆盖」具体指什么

| 场景 | 结果 |
|---|---|
| A 和 B 同时打开这个页面 | 各自一个 `dsessions` 行，各查各的房间与余额 |
| 访客登录 | 不写 `meta.session`，本站主人的 nofish 登录不受影响（有用例盯着） |
| 同一手机号再次登录 | 复用 `dusers` 行，房间按 `(user_id, 4 个 code)` upsert，不重复插 |
| 上游解绑了房间 | 下次登录时 `save_rooms` 会把这个房间从 `drooms` 删掉 |
| 令牌过期 / 手动退出 | 删除 `dsessions` 行，下次要重新收短信 |

### 6.3 页面路由

| 路径 | 谁能看 | 内容 |
|---|---|---|
| `/login` | 未登录 | 登录页（手机号 + 学校 + 图形验证码 + 短信码），成功后跳 `/` |
| `/` | 已登录 | 本地有在采集的房间 → 完整仪表盘；只有余额 → 简版「我的寝室」 |
| `/me` | 已登录 | 简版「我的寝室」：自己的房间 + 上次查到的余额 |
| `/setup` | 站主 | 采集账号（nofish）的重新登录向导 |
| `/import` | 已登录 | 粘贴抓包请求 |
| `/direct` | — | 301 到 `/login`（老链接） |

主页面按「这个账号名下的房间在本地有没有被采集」自动选：有历史就给仪表盘，
没有就给简版页，不会把别人的数据端出来。

### 6.4 为什么还是会要你重新收短信

`shiroJID` 的有效期由易校园决定，不是我们能续的。实测 H5 的票据十几分钟就废，
App 登录的票据明显更久（具体多久还在观察）。所以设计成：

```
日常点开 → 命中令牌 + 票据还有效 → 直接出余额（不用短信）
票据被上游作废 → 页面上说「登录已失效」，手机号还在，点一次获取验证码即可
```

---

## 7. 配置

```yaml
direct:
  enabled: true
  school_code: "10356"        # 默认学校
  school_name: 中国计量大学
  session_ttl_minutes: 30     # 登录过程的一次性会话
  max_sessions: 500
  persist_days: 30            # 浏览器记住登录多少天
  send_interval_seconds: 60
  phone_daily_limit: 6
  ip_daily_limit: 20
  start_hourly_limit: 60      # 每 IP 每小时最多建几次登录会话
  timeout: 20
  verify_tls: false
  app_all_version: "7.3.6"    # 易校园改版时改这里
  client_id: "65l3attk4r095ib"
```

`max_sessions` 满了会丢最老的**一次性登录会话**（不影响已持久化的账号）。
**多进程/多机部署**时 `DirectSessions`（登录过程）要换 Redis；
`dusers/dsessions/drooms` 在 SQLite 里，多进程共享没问题（注意 WAL 与并发写）。

---

## 8. 安全边界（硬性）

1. 短信只发到用户填的手机号本人，**没有**「输入别人手机号直接查」。
2. 图形验证码必须人眼看图输入，**不做 OCR / 打码平台 / 自动绕过**。
3. 凭据处理（本次改为持久化后重新划线）：
   - `shiroJID`：**可以落库，但必须加密**（AES-128-CTR + HMAC，密钥 `data/direct.key`），
     接口和页面都不返回它；
   - 浏览器令牌：库里只存 sha256，原文只在用户自己的 `localStorage`；
   - 短信码：只在一次请求里用，不存；
   - 完整手机号：接口只返回 `133****5522` 打码值；用户自己的号码存在自己浏览器里，
     方便失效后一键重登。
4. 每个账号只能选**自己**房间列表里的序号，拿不到别人房间的数据。
5. 登录过程 30 分钟过期 + 手机号/IP 双限流，避免把上游配额和账号风控烧掉：
   同一手机号 60 秒一次、每天 6 次；同一 IP 每天 20 次；
   `/start` 每 IP 每小时 60 次（它不花短信，但每次打两下上游）。
6. 备份/迁移注意：`data/power.db` + `data/direct.key` 要一起拷，
   只拷库会导致已存登录解不开（表现为要求重新验证，不会崩）。

---

## 9. 测试

```bash
python -m unittest discover -s tests -v
```

### 9.1 验证进度

| 步骤 | 状态 | 怎么验的 |
|---|---|---|
| ① `security/token` | ✅ **真实上游通过** | 用随机 deviceId 直接请求，拿到 56 位 `securityToken`（`level=0`） |
| ② `imageCaptcha` | ✅ **真实上游通过** | 返回 `data:image/jpeg;base64,...`（约 4.8 KB） |
| ③ `appSecurityToken` | ✅ 算法通过 | 用①的**真实** token 解密-重加密，明文 6 段结构正确 |
| ③ 发短信 | ⏳ 待真实手机号 | 需要本人号码 + 人眼看图输入 |
| ④ `doLoginByVerificationCode` | ⏳ 待短信码 | 同上 |
| ⑤–⑧ 授权码 / shiroJID / 房间 / 余额 | ⏳ 待登录成功 | 用 mock 上游跑通（含验签、Cookie、rows 在顶层） |

也就是：**联网能验的部分都验过了**（签名被上游接受、AES 与真 token 对得上、
验证码图能取到）；剩下四步必须由本人在本机输一次短信码才能走完。

### 9.2 离线用例（78 个）

- **AES**：FIPS-197 标准向量、与 `cryptography` 交叉验证、PKCS7 往返、坏填充。
- **签名**：8 组官方 Go 测试向量、空串跳过、deviceId 生成、手机号打码。
- **appSecurityToken**：解出来的明文结构、`s` 的二次 MD5、长度校验。
- **全链路（mock 上游）**：mock 会**自己验签**、解 `appSecurityToken`、校验
  `Cookie: shiroJID`、`queryBind` 的 `rows` 在顶层、`queryRoomSurplus` 的参数；
  另外覆盖「网关只认 JSON 时自动换格式再试」、验证码图片 mime 识别。
- **接口**：`/api/direct/*` 全流程、缺图形码、验证码错、短信码错、限流 429、
  会话不存在、会话 TTL、`start` 每小时上限、学校列表与错误学校名、响应里无凭据。
- **多用户**：两个会话各查各的；令牌换用户拿不到别人房间；
  登录全程 `save_session` / `clear_session` 调用 0 次（不碰 nofish 登录态）。
- **持久登录**：登录发令牌 → 不带 `session_id` 只凭令牌查余额 → `session` 恢复 →
  `logout` 失效 → 上游票据被作废时返回 `kind=relogin` 且不重复撞上游。
- **存储层**：`dusers` 幂等 upsert、令牌只存哈希、`shiroJID` 密文入库、
  换密钥后解不开（返回空而不是崩）、过期清理、房间 upsert/删除、余额回写。
- **CLI**：`cmd_direct_login()` 全流程 + 图形码落图 + 凭据不进终端。
- **配置**：自带 YAML 子集解析器（没有 PyYAML 的机器）能正确读 `direct` 段。

**还没做的验收**：用真实手机号跑一次（收到短信 → 登录成功 → 看到自己的房间和余额）。
这一步需要本人手机号 + 短信码，按约定不在对话/日志里回显，需要本人在本机执行：

```bash
python cli.py direct-login --phone <手机号> --school 10356 --open
```

---

## 10. 排错

| 现象 | 原因 / 处理 |
|---|---|
| `图形验证码已失效` / `token无效` | `securityToken` 过期，点「换一张」重取 |
| `验证码错误` | 图形码输了但不对；换一张再输 |
| `发送太频繁，请 N 秒后再试` | 本地 60 秒限流，或上游自己的风控 |
| `短信发送超限，请明天再来` | 上游当日配额用完，**不要换 IP 硬刷** |
| `您已输错 3 次，账户被锁定 15 分钟` | 短信码输错 3 次，等 15 分钟 |
| `没拿到授权码` | `getCodeV2` 没回 302；多半是 `schoolCode` 错或上游改版 |
| `上游没有下发会话票据（shiroJID）` | `getUser4Authorize` 没给 Cookie；看返回的 `message` |
| `登录成功但没绑定寝室` | 该账号在电费系统里没有房间；先易校园 App 里绑定 |
| `需要重新验证一次手机号` | 上游把票据作废了（`kind=relogin`）；手机号还在，再收一次短信即可 |
| `登录已过期，请重新验证手机号` | 浏览器令牌过期（`persist_days`，默认 30 天）或被 `logout` 删了 |
| 查到的 `amount` / `surplus` 对不上 nofish | 见下一条 |

### 关于 `amount` 和 `surplus`

实测响应里 `amount`（元）和 `surplus`（度）会同时出现，`isShowMoney` / `isShowSurplus`
决定前端显示哪个。**两者的准确含义还没用新鲜数据对照过**，所以 `/direct` 页面以
`amount`（元）为主、同时显示 `surplus`（度），不做「哪个是权威值」的判断。
现有采集适配器仍然优先 `amount` 并写 `unit="cny"`。

---

## 11. 已知限制 / 下一步

1. **未做真实手机号端到端**（需要本人操作，见第 9 节）。
2. `shiroJID` 的有效期没实测；H5 的 token 十几分钟就没了，App 登录的应更长（待验证）。
   这也是「多久要重登一次」的唯一决定因素。
3. 登录过程的一次性会话还是单进程内存；多进程要换 Redis
   （账号/令牌/房间在 SQLite，多进程没问题）。
4. 图形验证码不支持语音验证码之类的备选通道。
5. 上游随时可能改版：`app_all_version` / `client_id` / 路径都已在配置或常量里，
   失败时先看 `kind` 和上游 `message`。
6. 没有账号密码、没有找回流程：手机号 + 短信是唯一的身份来源，令牌丢了就重新验证。
7. 只允许本人查询；公开部署前需要隐私政策、日志脱敏（已做）和更严格的配额。
8. `data/direct.key` 丢了 → 所有已存 `shiroJID` 解不开（会提示重新验证），不会崩，但要重登一轮。

---

## 12. 参考

- 协议对照（只读，未复制代码）：[`zjutjh/yxy-go`](https://github.com/zjutjh/yxy-go)
  - `internal/utils/yxyClient/sign.go`、`base.go`
  - `internal/logic/login/sendCodeLogic.go`、`loginByCodeLogic.go`
  - `internal/manager/auth/electricityAuthManager.go`
  - `internal/logic/electricity/getElectricitySurplusLogic.go`
  - `internal/consts/consts.go`
