# 规则引擎 v2 影子评测与人工复核记录

> 复核日期：2026-07-27
> 评测对象：声明式规则包 `builtin@1.0.0` 与冻结的 v1 正则基线
> 结论：v2 达到切换基线；生产构建只保留 v2，v1 仅作为 test-only fixture

## 评测方法

- 使用 `src-tauri/tests/fixtures/rules/samples.json` 的 56 条人工标注样本；14 条规则各有正例、反例和边界样本。
- 同一份 `TrafficView` 同时交给 v2 与冻结的 v1 求值器。
- 每条结果写入内存 SQLite 的临时表 `rule_shadow_diff`，verdict 固定为 `both`、`v2_only`、`legacy_only` 或 `none`。
- 只对样本明确标注的 `rule_id` 计算 TP、FP、FN；同一流量意外命中其它规则时写入 `skip_reason = 样本未标注该规则`，不把未标注项算成任一引擎的对错。
- 测试断言 v2 的 FP/FN 均为 0、没有相对 v1 的回退，并锁定所有出现差异的规则集合。本轮另有 2 条跨规则命中因“样本未标注该规则”跳过计分。

## 逐规则结果

| rule_id | v2 TP/FP/FN | v1 TP/FP/FN | 人工结论 |
|---|---:|---:|---|
| `admin-console-path` | 2/0/0 | 2/0/0 | 一致 |
| `cookie-no-httponly` | 3/0/0 | 1/0/2 | v2 正确按单个 Cookie 判断属性 |
| `cookie-no-secure` | 3/0/0 | 1/0/2 | v2 不再把其它 Cookie 或 Cookie 值中的 `secure` 当成属性 |
| `cors-wildcard` | 2/0/0 | 2/1/0 | v2 只接受完整的 `*`，不误报 `*.example.com` |
| `debug-actuator-endpoint` | 2/0/0 | 2/0/0 | 一致 |
| `internal-ip-leak` | 2/0/0 | 2/0/0 | 一致 |
| `jwt-exposed` | 2/0/0 | 2/0/0 | 一致 |
| `password-in-request-body` | 2/0/0 | 2/0/0 | 一致 |
| `path-traversal-param` | 2/0/0 | 2/0/0 | 一致 |
| `sensitive-file-access` | 2/0/0 | 2/0/0 | 一致 |
| `sensitive-param-in-url` | 2/0/0 | 2/0/0 | 一致 |
| `server-version-leak` | 2/0/0 | 2/0/0 | 一致 |
| `sql-error-leak` | 2/0/0 | 2/0/0 | 一致 |
| `stack-trace-leak` | 2/0/0 | 2/0/0 | 一致 |
| **合计** | **30/0/0** | **26/1/4** | **全部差异均为经复核的 v2 改进** |

## 差异复核

出现标注差异的规则固定为以下三条：

1. `cookie-no-httponly`：v1 的全局 `must_absent` 会因另一条 Cookie 带有 `HttpOnly`，或 Cookie 值本身出现 `httponly` 字样而漏报。
2. `cookie-no-secure`：v1 会因另一条 Cookie 带有 `Secure`，或 Cookie 值本身出现 `secure` 字样而漏报。
3. `cors-wildcard`：v1 对整段 Header JSON 做前缀正则，错误地把 `*.example.com` 识别成完整通配符。

人工复核确认这些差异都符合 v2 的结构化字段语义；没有发现 v2 回退。未标注的跨规则命中继续保留在临时差异表中，并以“样本未标注该规则”为跳过原因，避免把缺少标签误当成 FP。

## 切换与清理决定

- 代理生产路径只调用声明式 v2；不在网络转发路径运行双引擎。
- 旧 `src-tauri/src/rules/builtin.rs` 已从生产源码树删除。冻结基线位于 `src-tauri/tests/fixtures/rules/legacy_v1.rs`，只在 `cfg(test)` 的影子评测中编译。
- 项目尚未公开发布，因此不存在可真实声称的公开“稳定一个发布周期”。本次以人工标注 shadow 闸门、完整质量门禁和生产 crate 单轨作为预发布切换依据；首次公开发布后的回滚观察期需另行记录。

复现命令：

```text
cargo test --manifest-path src-tauri/Cargo.toml rules::shadow -- --nocapture
cargo test --manifest-path src-tauri/Cargo.toml --test rules_pack
```
