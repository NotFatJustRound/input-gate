# CHANGELOG

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
