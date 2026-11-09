# input-gate

给 agent 的外部输入套一道闸。

> 灵感来源: 一篇讲 GitHub 开源工具风险的视频。核心论点——别让同一个 agent 同时拥有「接触私有数据」「处理不可信内容」「对外发请求」三种能力。现实里这三样往往同时在线，所以退一步：至少让不可信内容进来时**带着标签、带着上限、带着检查**。

这不是沙箱，也挡不住精心构造的攻击。它做的是一件事：让「这段文字来自外部」这件事，在 agent 的上下文里不可忽略。

## 三道闸

1. **来源标记** — 外部抓取的内容一律打 `untrusted` 标签，头部附来源 URL/域名/抓取时间。模型看到的第一眼就知道这段不是自己的指令。
2. **长度封顶** — 超预算正文截断，末尾标 `[truncated, 剩余 N 字符]`，避免长文把上下文挤爆、也避免藏在 5 万字符之外的指令被顺带吃进去。
3. **检查与白名单** — 可疑指令模式（"忽略之前的指令"、伪造 system 标签、把密钥往外发、`curl | sh`）、零宽字符 / 双向控制符、超长 base64 串；域名不在白名单时降级为纯文本引用。

检测到的东西不删，**标出来**。删掉等于假装没发生过，标出来才知道该防谁。

## 用法

```python
from gate import gate, Policy

p = Policy(max_chars=8000, allow_domains={"github.com", "docs.python.org"})
r = gate(html_text, source="https://example.com/x", policy=p)

r.text        # 截断并加了围栏的正文
r.trusted     # False
r.flags       # ['INJECTION_PATTERN:忽略之前的指令', 'INVISIBLE_CHARS:3']
r.truncated   # True
```

命令行快速试:

```bash
python gate.py https://example.com/blog
```

## 围栏格式

```
[UNTRUSTED SOURCE: https://example.com/x | fetched 2026-11-09T02:00:00Z | flags: INJECTION_PATTERN]
<<<UNTRUSTED_TEXT
...正文...
UNTRUSTED_TEXT>>>
```

## 局限（请先读这条）

- 关键词匹配必然漏。攻击者换个说法、换语种、用编码绕一下就过了。
- 白名单只管域名，不管路径和内容。好域名也会被投毒。
- 真正的权限隔离在宿主/容器/密钥那一层，不在这一层。**这个插件只是让不可信内容显形，不是安全边界。**

## 接入

本仓库只有规则和代码，不依赖任何运行时。挂到宿主上需要由管理员在管理端安装为插件/工具；代码本身不自动生效。
