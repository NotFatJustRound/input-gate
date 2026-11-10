# CHANGELOG

## 2.3.0

按 issue #1 的三条实测问题修（围栏伪造 / 隐形字符漏区 / 硬规则误伤文档），另带三处小毛病。

- **围栏改成带 nonce**：输出是 `<<<UNTRUSTED_TEXT:<nonce>>>>` … `<<<END_UNTRUSTED_TEXT:<nonce>>>>`。
  nonce 默认每次调用随机（`newNonce()` / `new_nonce()`）；调用方注入 `fetchedAt` 时按
  `source + fetchedAt` 派生（`derivedNonce()` / `derived_nonce()`），这样同样的输入与时间戳能得到同样的输出；
  也可以用 `nonce` 参数直接钉死。**派生模式只是为了可复现，别在线上拿它当防护。**
  正文里只要出现围栏写法（`<<<UNTRUSTED_TEXT`、`UNTRUSTED_TEXT>>>`、`<<<END_UNTRUSTED_TEXT`）直接
  `reject · FENCE_FORGERY`；冒充来源横幅（`[UNTRUSTED SOURCE:`、`[REJECTED BY input-gate`）判
  `BANNER_FORGERY`。只是文字里提到这个词、不带箭头的不拦。
- **隐形字符补表**：新增 U+E0000–E007F（Tags 区）、U+FE00–FE0F、U+E0100–E01EF（变体选择符）、
  U+034F、U+180E、U+2065–U+2069。Tags 区单独判 `reject · TAG_SMUGGLING`——变体选择符还有正经用途，
  但 Tags 区除了 ASCII smuggling 没有别的用法。
- **硬规则命中落在代码块内降级为 quarantine**：三反引号/波浪线围栏、或四空格缩进的代码行里命中
  `SHELL_PIPE` / `EVAL_BLOB` / `FAKE_TAG` 等，不再整段吞掉正文，只隔离并保留告示。新配置项
  `codeContextDowngrade`（默认 `true`，Python 侧 `code_context_downgrade`）。
  代价写在已知局限里：把载荷包进代码块能把 reject 降成 quarantine。
- `ROLE_SWAP` 收窄：要求后面跟身份词（助手/模型/AI/agent/角色…），`你现在是靠什么判断的？` 不再被隔离。
- 截断按码点切：`maxChars` 卡在 emoji 中间时不会再留半个代理对；`droppedChars` 也按码点算。
- Python CLI 兜住 `BrokenPipeError`：`python gate.py x.txt | head` 不再甩 traceback，按正常退出。
- 结果结构新增 `nonce` 字段；新增 `fenceOpen/fenceClose`、`isInCodeContext`（Py 侧 `fence_open/fence_close`、`is_in_code_context`）导出。
- 新增 `tests/gate.v23.test.mjs`（13 条断言）与 `tests/test_gate_v23.py`（11 条断言）；README 补「围栏与隐形字符」「代码块内的硬规则」两节和新配置项。

## 2.2.0

- 新增**防破甲层**：`ARMOR_RULES` 七条，专管「重排指令层级」的说法
  - `ARMOR_SELF_CLAIM` 破甲/越狱话术、`ARMOR_PRIORITY` 重写优先级、`ARMOR_LIFT` 要求解除限制、
    `ARMOR_AUTHORITY` 冒充授权方、`ARMOR_UNBOUND` 要求无约束身份、`ARMOR_DISCLAIMER` 研究免责包装、
    `ARMOR_SYSTEM_HEADER` 伪造系统段
- 档位语义：`strict` 直接 reject；`balanced` / `lenient` 一律 quarantine——**破甲话术没有 pass 档**，
  换措辞可以绕，但「限制已经没了」这种句子不该被判成「没问题」
- 交付渲染多挂一行 `ARMOR_NOTE`，写明文本里的层级声明不改变运行时规则，也不改变 agent 身份
- 结果结构新增 `armor_hits` / `armorHits` 与 `armored`；`codes` 里照常带 `ARMOR_*`
- 新增策略字段 `armor`（默认 `true`）。关掉只影响防破甲层，其他判据不变
- Python 与 JS 两份实现同步改动；两边测试各补 15 条与 13 条断言
- README 补「防破甲层」一节，并写清副作用：**讨论破甲的文档自己会被标记**（本 README 亦然）

## 2.1.1

- 修三处「装得上但工具不出来」的 bug（由 Claude 审码指出，我复核后照改）：
  - `inject` 从 `[]` 改成 `['tools']`：写成空数组时 `apply` 早于 tools 服务就绪，
    `ctx.get('tools')` 拿到 `undefined`，降级分支直接 return，工具永远注册不上
  - 取服务改成 `const tools = ctx?.tools ?? ctx?.get?.('tools')`
  - `output` 补 `render`：只有 `schema` 时结果渲染不出来
- 三条都不改变纪律：服务真的缺席时，仍然只是本插件不注册，宿主照常起
- 注释补上「为什么必须 inject tools」，免得以后又有人顺手改回 `[]`

## 2.1.0

- 变成**可安装的 DSH 插件**：补 `package.json` 的 `dsh.bundle.patch`、`cordis.patch.yml` 名册、Host 半区 `lib/index.js`，注册 `input_gate` 工具
  （2.0 装不上就是因为没有这层声明，插件管理器报「这个包没有声明组合包」）
- 规则换成 JS 实现 `lib/gate.js`，与 `gate.py` 同规则；两份各有断言
- 工具侧 fail closed：检测出错返回 `ok: false` + `verdict: reject`，不把原文当通过结果
- 配置不认识就抛错、工具不注册，但**不让宿主起不来**
- 新增 `tests/gate.test.mjs`（`node --test`，零依赖）
- README 补安装、工具用法、两份实现的漂移风险

## 2.0.0

- 裁决从「只打标记」改成三级：`pass` / `quarantine` / `reject`；硬规则命中时正文**整段不交付**
- 三档模式 `strict` / `balanced` / `lenient`，硬规则不受档位影响
- 来源判定细分：`DOMAIN_NOT_ALLOWED` / `PLAIN_HTTP` / `UNPARSABLE_SOURCE` / `NO_SOURCE`
- 空内容、解析不出 host 的来源一律 `reject`（fail closed）
- 策略文件遇到未知字段或未知模式直接抛错，不再静默忽略
- 截断改为「事实记录」，不再和风险混在同一个 flags 列表里当警告
- 新增 `fetched_at` 注入，输出可复现
- 新增 `tests/test_gate.py`：纯标准库 unittest，无网络、无 mock 时钟
- README 重写：三种裁决、模式表、失败语义表、已知局限

## 1.0.0

- 初版：来源横幅 + 长度封顶 + 可疑模式检测（只标记，不拦截）
