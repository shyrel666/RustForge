# Phase 1 · Scope、MITM 代理与有界流量工作台 — 当前说明

> 实现核查日期：2026-07-29。本文描述当前代码，不再保留早期“先收完整正文、入库时再截断”的实现说明。

## 交付内容

### 统一授权边界

- `src-tauri/src/authorization/scope.rs` 是代理和 Repeater 共用的 `ScopePolicy`。
- 项目 Scope 保存前会规范化为 host-only 条目：ASCII/IDNA 域名、小写、去尾随点、规范 IPv4/IPv6；支持精确 host 和 `*.example.com`。
- 通配条目覆盖 apex 和其子域，但不允许对 IP 使用通配符。显式端口只是输入便利，不进入授权身份。
- 无当前项目、项目不存在、Scope 为空、Scope 损坏或 host 未命中时采用 fail-closed 判定。
- Repeater 的完整 URL 校验还会拒绝非 HTTP(S) scheme、userinfo、缺失 host、歧义反斜杠和非法端口。

### MITM 与 CA

- `src-tauri/src/proxy/interceptor.rs` 基于 hudsucker 0.25：Scope 内 HTTPS 才执行 MITM 并记录；Scope 外 CONNECT 走盲隧道，普通 HTTP 直接透传且不记录。
- 代理外流量不会进入捕获缓冲，也不会进入规则队列。Scope 决定 RustForge 能否解密/记录，不是系统防火墙；浏览器自身仍可能访问 Scope 外目标。
- `src-tauri/src/proxy/ca.rs` 生成 `RustForge MITM CA`，私钥采用安全临时文件、同步和原子重命名写入。
- Windows 使用仅当前用户 SID 的 ACL；Unix 使用收紧后的目录/文件权限。已有材料不完整、符号链接或权限无法收紧时停止代理。
- 私钥 PEM 使用 zeroize 容器；导出命令只能复制公钥证书，不能返回或导出私钥。

### 有界流式捕获

- `src-tauri/src/proxy/body_capture.rs` 使用 tee body：每个 frame 原样继续转发，同时只保留有界前缀。
- 每个请求/响应的线缆捕获上限 `MAX_WIRE_CAPTURE_BYTES = 1 MiB`；实际 `wire_size` 按观察到的数据帧累计，不相信 `Content-Length`。
- gzip、x-gzip、deflate、br 解压后另受 `MAX_DECODED_CAPTURE_BYTES = 1 MiB` 限制；多层编码按反序解码，每一层均有界。
- 保存 `wire_size`、`captured_size`、`truncated` 和稳定 `decode_status`。状态覆盖未收到、空、文本/二进制、正常解压、编码不支持、编码前截断、解压截断、解码失败、流错误和流未完成。
- `HeaderMap` 序列化时保留重复值顺序；单值为字符串，多值为数组，`Set-Cookie` 不做逗号或换行合并。
- 上游失败会留下 `status = NULL`、`resp_decode_status = not_received` 的审计流量，但这类流量不能成为 Finding confirmed 的合格 Evidence。

### 流量工作台

- `TrafficView.vue` 显示代理状态、Scope/证书入口、方法/状态/host/path 过滤、规则标签和捕获状态。
- 列表初始窗口为 200 条，“加载更多”扩大窗口；`count_traffic` 使用相同过滤条件返回总数。
- 详情按 `decode_status` 展示文本或 base64，并明确提示截断、二进制、解码失败或未收到响应。
- `traffic:new` 先推送流量；后台规则完成后通过 `traffic:tags` 增量补写标签，规则求值不占用转发写事务。

## 关键安全语义

| 场景 | 当前行为 |
|---|---|
| 无当前项目 / 空 Scope | 不 MITM、不记录、不提交规则；Repeater 拒绝发包 |
| Scope 外 HTTPS | CONNECT 盲隧道，不解密、不记录 |
| Scope 外普通 HTTP | 原流量透传，不记录 |
| 大正文 / chunked / 错误长度 | 继续转发，捕获缓冲最多 1 MiB |
| 压缩炸弹 | 线缆和每层解压均受独立 1 MiB 上限 |
| 下游取消或流错误 | 保存有界前缀并标记 `stream_incomplete` / `stream_error` |
| 重复响应头 | 有序数组保存，不折叠 `Set-Cookie` |

## 自动验证

相关测试覆盖：

- 精确/通配域名、apex、大小写、尾随点、IDN、IPv4/IPv6、userinfo 混淆和非法 URL。
- 代理与 Repeater 对同一 host 的授权一致性，以及 Repeater 越界时没有 socket 连接。
- 大/未知长度、chunked、错误声明长度、gzip/deflate/br、解压炸弹、二进制、无效 UTF-8、空正文和重复 Header。
- 捕获峰值随配置上限增长，而不是随完整响应大小增长。
- CA 原子写、私钥权限、重载和只导出证书。

复现完整门禁：

```text
cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml --all-targets
pnpm check
```

## 手工验收

1. 新建项目并加入一个明确授权的 host；启动代理前确认 Scope 规范化结果。
2. 安装 CA，将浏览器代理指向 `127.0.0.1:8080`，访问 Scope 内 HTTPS，确认出现可读流量。
3. 访问 Scope 外 HTTPS，确认页面可按浏览器网络策略访问，但 RustForge 不解密、不记录。
4. 对本地授权测试服务发送超过 1 MiB、chunked 和压缩响应，确认浏览器收到完整响应，而详情页显示有界快照与截断状态。
5. 发送多个 `Set-Cookie`，确认详情页逐项展示。

## 已知限制

- Scope 只表达 host，不能表达路径、端口、时间窗或测试方法；授权更窄时不能仅依赖 RustForge Scope。
- WebSocket 当前只转发，不记录消息历史；SSE、gRPC、GraphQL 没有专用语义视图。
- 证书钉扎和要求客户端证书的站点可能无法 MITM，这是预期限制。
- 流量列表仍是“扩大窗口后重拉”，不是十万级虚拟列表或游标分页。
