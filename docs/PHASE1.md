# Phase 1 · MITM 代理与流量工作台 — 完成说明

## 交付内容

**后端（src-tauri/src/proxy/）**
- `ca.rs` — rcgen 0.14 生成自签名根 CA（`RustForge MITM CA`，有效期 2024–2035），
  持久化在 `app_data_dir/ca/`；SHA-256 指纹、导出、`certutil -user -addstore Root`
  一键安装（当前用户 store，系统弹安全警告由用户确认）、信任状态检测
- `interceptor.rs` — hudsucker 0.25 `HttpHandler` 实现：
  - `should_intercept_connect`：**Scope 白名单外的 HTTPS 直接盲隧道，不解密不记录**（红线）
  - `handle_request/handle_response`：收全量 body（存库截断 1 MiB）→ 解析 → 落 `traffic` 表 → `FlowSink` 推送
  - `handle_error`：上游失败也落库（status 为空），回 502
  - `FlowSink` trait 解耦 Tauri：生产 = `TauriSink`（emit `traffic:new`），测试 = VecSink
- `mod.rs` — `ProxyManager`：启动（先绑端口同步报错）/优雅停机（oneshot + hudsucker graceful shutdown）/状态广播（`proxy:status` / `proxy:error`）

**命令（commands.rs 新增）**
`start_proxy / stop_proxy / proxy_status / get_ca_info / export_ca_cert /
install_ca_cert / reveal_ca_cert / list_traffic / get_traffic_detail /
clear_traffic / update_project_scope`

**前端**
- `TrafficView.vue` — 启动/停止 + 状态徽章、方法/状态/host+path 过滤（搜索 300ms 防抖）、
  实时表格（事件追加，上限 500 条）、详情抽屉（请求/响应头表格 + body 文本/base64）
- `CertGuideDialog.vue` — 信任状态、指纹、一键安装、导出、手动步骤、Firefox 与代理设置说明
- `ScopeDialog.vue` — 标签式白名单编辑（`example.com` / `*.example.com` / IP）

## 关键 API 核实记录（hudsucker 0.25.0，2026-07-15 发布）

凭记忆会写错的点，全部对照 crate 源码确认：

| 记忆/旧版 | 0.25.0 实际 |
|---|---|
| `RcgenCertificateAuthority::new(key_pair, cache_size, provider)` | `RcgenAuthority::new(Issuer<'static, KeyPair>, u64, CryptoProvider)`（rcgen 0.14 `Issuer::from_ca_cert_pem`） |
| `RequestContext/ResponseContext` | 统一 `HttpContext { client_addr }` |
| 只有 handle_request/response/error | 新增 `should_intercept_connect` / `should_intercept_tls`（正好用于 Scope 红线） |
| handler 生命周期不明 | 源码确认：每请求 clone 一次，同请求的 req/resp 回调作用在同一 clone → 可用字段暂存 pending |
| `body.collect()` 不可用 | `Body` 实现 `http_body::Body`，`http_body_util::BodyExt::collect` ✓ |

rcgen 0.14 CA 生成：`CertificateParams{ is_ca: IsCa::Ca(BasicConstraints::Unconstrained), key_usages: [KeyCertSign, CrlSign, DigitalSignature], ... }` +
`KeyPair::generate()`（ECDSA P256）+ `params.self_signed(&key)`。

rustls provider：`aws_lc_rs`（tokio-rustls 默认特性链带入，需 cmake——VS BuildTools 自带：
`D:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin`）。

## 验证结果

- `cargo test`：3 项全过
  - `scope_matching`（白名单匹配规则单测）
  - `mitm_https_end_to_end`（无 GUI 全流程：CONNECT → TLS 解密 → 转发 → 落库 → 事件）
  - `out_of_scope_not_recorded`（Scope 外只转发不记录）
- `cargo build` / `pnpm build` 通过；`pnpm tauri dev` 正常启动

## 浏览器手工验收步骤（对应 Phase 1 验收标准）

1. `pnpm tauri dev`，首次确认授权声明，左下角新建项目
2. 流量页 → 「Scope」加入目标域名（如 `*.example.com`）
3. 「证书引导」→ 一键安装（系统弹安全警告点"是"）→ 状态变绿"已信任"
4. 「启动代理」；系统代理或 SwitchyOmega 指向 `127.0.0.1:8080`
5. 浏览器访问 Scope 内 HTTPS 站点 → 流量实时入表，点击行看详情

## 已知限制（后续 Phase）

- gzip/br 压缩响应体按原字节存储，详情里显示为 base64（hudsucker `decoder`
  特性已开，Phase 2 做详情页解码预览）
- WebSocket 目前只转发不记录（计划 Phase 5）
- 证书钉扎（HPKP）/ 客户端证书站点天然无法 MITM，属预期行为
