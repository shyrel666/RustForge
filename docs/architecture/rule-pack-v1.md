# 声明式被动规则包 v1

> Schema：`RULE_SCHEMA_VERSION = 1`；内置包：`builtin@1.0.0`；实现核查日期：2026-07-29；源码真值：[`rules/schema.rs`](../../src-tauri/src/rules/schema.rs)、[`loader.rs`](../../src-tauri/src/rules/loader.rs)、[`engine.rs`](../../src-tauri/src/rules/engine.rs)、[`builtin-v1.json`](../../src-tauri/src/rules/packs/builtin-v1.json)。

规则包 v1 是只读、声明式、可审计的本地初筛格式。它只能选择已捕获的有界 HTTP 字段并比较标量，不能执行脚本、访问文件、创建进程、发送网络请求或改变 Finding 状态。

## 包与规则结构

```json
{
  "schema_version": 1,
  "pack_id": "builtin",
  "version": "1.0.0",
  "source": "rustforge-builtin",
  "description": "本地初筛；结论一律待人工验证",
  "rules": [
    {
      "rule_id": "cookie-no-httponly",
      "version": "1.0.0",
      "source": "rustforge-builtin",
      "name": "Cookie 缺少 HttpOnly",
      "description": "逐条 Set-Cookie 独立判定",
      "verify_hint": "确认该 Cookie 是否为会话凭据",
      "severity": "low",
      "confidence": 65,
      "tag": "Cookie",
      "vuln_type": "Cookie 安全属性缺失",
      "references": [
        { "framework": "owasp-top10", "version": "2021", "id": "A05" },
        { "framework": "cwe", "version": "4.20", "id": "CWE-1004" }
      ],
      "condition": {
        "operator": "for_each",
        "target": "response_cookie",
        "condition": {
          "operator": "missing",
          "selector": {
            "target": "response_cookie",
            "extractor": {
              "kind": "cookie",
              "field": "attribute",
              "attribute": "httponly"
            }
          }
        }
      }
    }
  ]
}
```

所有结构使用 `deny_unknown_fields`；拼错或多余字段不会被静默忽略。

### 包字段

| 字段 | 约束 | 语义 |
|---|---|---|
| `schema_version` | 必须为 1 | 格式兼容边界，不等同于 pack 版本 |
| `pack_id` | 非空 | 包稳定身份 |
| `version` | 非空 | 本次求值与 provenance 使用的包版本 |
| `source` | 非空 | 规则来源标识 |
| `description` | 非空 | 包用途与限制 |
| `rules` | 1–256 条 | 同一包内 `rule_id` 唯一 |

### 规则字段

| 字段 | 约束 | 语义 |
|---|---|---|
| `rule_id` | 非空、包内唯一 | 规则稳定身份；语义真正改变时应换 ID |
| `version` | 非空 | 该次命中审计记录的规则版本 |
| `source` | 非空 | 规则级来源 |
| `name` / `description` | 非空 | Finding 标题与命中解释基础 |
| `verify_hint` | 非空 | 人工验证建议，不是执行脚本 |
| `severity` | `info/low/medium/high/critical` | medium 以上才升级 Finding |
| `confidence` | 1–100 | 规则自评；截断证据命中会压到 ≤ 40 |
| `tag` | 非空 | 所有命中都可追加到 Traffic 标签 |
| `vuln_type` | 非空 | Finding 类型 |
| `references` | 至少 1 个 | 必须命中内置固定版本知识 registry |
| `condition` | 深度 ≤ 16 | 只允许下述声明式条件 |

## 条件运算符

| operator | 字段 | 行为 |
|---|---|---|
| `equals` | `selector`, `value`, `case_sensitive?` | 完整标量相等 |
| `contains` | `selector`, 非空 `value`, `case_sensitive?` | 标量包含 |
| `regex` | `selector`, `pattern` | Rust `regex`；加载时完成预算化编译 |
| `exists` | `selector` | 至少一个候选存在 |
| `missing` | `selector` | 候选不存在 |
| `greater_than` / `greater_or_equal` | `selector`, number `value` | 候选解析为数值后比较 |
| `less_than` / `less_or_equal` | `selector`, number `value` | 候选解析为数值后比较 |
| `all` | 非空 `conditions` | 所有子条件命中 |
| `any` | 非空 `conditions` | 任一子条件命中 |
| `not` | `condition` | 逻辑取反 |
| `for_each` | cookie `target`, `name?`, `condition` | 对每条请求/响应 Cookie 独立评价；首版仅支持 Cookie |

`for_each` 用来避免全局缺失判断的经典误差：另一条 Cookie 带 `HttpOnly` 不能掩盖当前 Cookie 缺失该属性。

## Selector target

| target | 字段路径前缀 | 说明 |
|---|---|---|
| `method` | `request.method` | HTTP 方法 |
| `url` | `request.url` | 完整捕获 URL；证据输出会脱敏 |
| `query` | `request.query` | URL query 项 |
| `request_header` | `request.header` | 请求 Header，可用 `name` 限定 |
| `response_header` | `response.header` | 响应 Header，重复值逐项保留 |
| `request_cookie` | `request.cookie` | `Cookie` 中的逐项 name/value |
| `response_cookie` | `response.cookie` | 每条 `Set-Cookie` 的 name/value/attribute |
| `request_body` | `request.body` | 有界、状态可用的请求正文 |
| `response_body` | `response.body` | 有界、状态可用的响应正文 |
| `status` | `response.status` | HTTP status |
| `content_type` | `response.content_type` | 响应 content type |

Header 和 Cookie 名按对应解析器做大小写无关匹配；query/form 字段名保持数据本身的语义。

## Extractor

| kind | 允许 target | 选项 / 限制 |
|---|---|---|
| `text` | 全部 | 默认提取器，读取目标文本标量 |
| `query` | 仅 `query` | `field = name/value/pair`，默认 value；percent-decode |
| `form` | 仅 request/response body | `field = name/value/pair`；按 URL encoded 表单解析 |
| `json_path` | 仅 request/response body | 只支持 `$.a.b`、`$.a[0].b`；最多 12 段；拒绝 `..`、通配、filter、表达式 |
| `cookie` | 仅 request/response cookie | `field = name/value/attribute`；请求 Cookie 不允许 attribute；指定 attribute 时归一化小写 |
| `jwt_metadata` | 任意能产生 token 字符串的 target | `alg/typ/kid/iss/aud/exp/nbf/iat`；只解码 metadata，不验证签名 |

每个 selector 最多展开 256 个候选。提取失败退化为无候选或诊断，不 panic、不调用外部能力。

## 加载期预算

| 项目 | 上限 |
|---|---:|
| 每包规则数 | 256 |
| 条件树深度 | 16 |
| 正则源码 | 512 bytes |
| 正则编译程序 size limit | 1 MiB |
| 正则 lazy DFA cache | 1 MiB |
| 正则语法 nesting | 24 |
| JSONPath 段数 | 12 |

loader 同时校验：

- JSON/schema version 和未知字段。
- 包/规则必填元数据、重复 rule ID、confidence 和 severity。
- 精确 `{framework, version, id}` 是否存在于知识 registry。
- operator 子节点非空、`for_each` target、selector/extractor 兼容性。
- 过长、编译展开爆炸或嵌套病态正则。

严格入口 `load_pack` 返回错误；生产容错入口 `load_pack_status` 把整个包设为 `Disabled`，保留经过秘密过滤的原因。禁用包求值为零命中并产生诊断，不影响代理。

## 求值期预算与数据语义

| 项目 | 上限 / 行为 |
|---|---|
| 单包单 Traffic wall-clock | 50 ms |
| 每 selector 候选 | 256 |
| 命中证据片段 | 160 chars |
| 截断正文命中 confidence | 最多 40 |
| worker queue | 256 jobs，非阻塞提交 |

- Traffic 已落库后才投递 `{project_id, traffic_id}`；队列不复制 1 MiB body，worker 消费时再读取有界快照。
- worker 是独立 OS thread，规则计算和阻塞 SQLite 写入不占用异步代理工作线程。
- headers、cookies、query、form、JSON 和 body 每包解析一次并在规则之间复用。
- 非文本、解码失败或不支持编码的 body 不会被当作正常文本候选。
- 超时停止后续求值，保留已经产生的命中并写 `timed_out` 与诊断。
- 队列满/断开时当前规则任务被丢弃，代理继续转发；submitted/completed/dropped/timed_out/failed 可在 UI 查看。

## 证据、指纹与 Finding

### 证据最小披露

- Cookie 证据永不包含值，只显示 name 和属性；属性值也遮盖。
- 通用证据先经过秘密过滤，再遮盖 JWT 和凭据 `key=value` 形态，控制字符压为空格，最后截断。
- regex/contains 只保留命中周围的小窗口，而不是复制完整正文。
- 截断来源设置 `incomplete_evidence = true`，并压低 confidence。

### 两层指纹

1. hit fingerprint：`rule_id + uppercase method + lowercase host + path without query + field_path` 的长度前缀 SHA-256。
2. Finding fingerprint：`project_id + hit fingerprint` 的长度前缀 SHA-256。

query 值和规则版本不参与身份：同一端点同一字段的重复请求、规则补丁升级不会炸出重复 Finding。pack/rule version 仍保存在 `finding_rule_hits`；如果规则语义已经变成另一个问题，应使用新的 `rule_id`。

### 持久化流程

1. 以 `(traffic_id, pack_id, pack_version)` 抢占 `rule_evaluations` 幂等键。
2. 将所有命中 tag 合并到 `traffic.rule_tags`。
3. 对 medium 以上命中按 Finding fingerprint 查重。
4. 新身份创建 pending Finding；旧身份只追加 `finding_traffic`、更新 occurrence/last_seen 和命中审计，不改人工 status。
5. 每个升级命中写 `finding_rule_hits`，保存 pack/rule version、field path、脱敏 evidence、confidence、incomplete 和 hit fingerprint。

## 内置包清单

| rule_id | severity | confidence | tag | 顶层 operator |
|---|---:|---:|---|---|
| `sensitive-param-in-url` | medium | 70 | 敏感参数 | regex |
| `password-in-request-body` | low | 50 | 口令字段 | any |
| `jwt-exposed` | info | 90 | JWT | any |
| `sql-error-leak` | high | 75 | SQL报错 | regex |
| `stack-trace-leak` | medium | 70 | 堆栈泄露 | regex |
| `debug-actuator-endpoint` | medium | 60 | 调试端点 | regex |
| `admin-console-path` | info | 50 | 后台路径 | regex |
| `sensitive-file-access` | medium | 65 | 敏感文件 | regex |
| `path-traversal-param` | medium | 65 | 路径穿越 | regex |
| `cors-wildcard` | low | 60 | CORS | regex |
| `cookie-no-httponly` | low | 65 | Cookie | for_each |
| `cookie-no-secure` | low | 65 | Cookie | for_each |
| `server-version-leak` | info | 70 | 版本泄露 | any |
| `internal-ip-leak` | info | 55 | 内网IP | regex |

这些规则是初筛，不是漏洞证明。low/info 仍会打标签，但不会自动创建 Finding；medium 以上创建的 Finding 仍需真实 Evidence 和人工接受才能 confirmed。

## 修改内置规则包

当前没有运行时导入入口。修改内置包时应：

1. 在 `builtin-v1.json` 修改声明式规则，不添加任何执行能力。
2. 语义兼容修订递增 rule/pack version；问题身份改变时新增 rule ID。
3. 使用已存在的精确标准引用；需要新增标准条目时先更新并校验知识包内容 hash。
4. 为正例、反例、边界和截断输入更新 `tests/fixtures/rules/samples.json`。
5. 运行 loader/engine/worker 单测、规则包验收和 shadow 评测。
6. 更新本文内置清单与 [`rule-shadow-evaluation.md`](rule-shadow-evaluation.md)（若基线变化）。

复现命令：

```text
cargo test --manifest-path src-tauri/Cargo.toml rules::
cargo test --manifest-path src-tauri/Cargo.toml --test rules_pack
```

2026-07-27 的冻结 v1 正则基线对比使用 56 条人工标注样本：声明式引擎得到 30 TP、0 FP、0 FN；详情和差异解释见 [rule-shadow-evaluation.md](rule-shadow-evaluation.md)。该评测证明固定样本上的迁移不回退，不代表规则能覆盖所有真实漏洞。
