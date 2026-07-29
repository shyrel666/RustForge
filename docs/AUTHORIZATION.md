# 授权测试声明与 Scope 边界

> 文档与实现核查日期：2026-07-29。本文不是法律意见；法律、合同、漏洞赏金规则和组织政策可能变化，执行前应由目标所有者与测试方共同确认。

RustForge 只适用于已取得明确书面授权的安全测试与本地学习环境。软件许可、能够访问某个站点、加入 Scope 或模型给出建议，都不构成对目标的测试授权。

## 书面授权至少应记录

1. 授权方：目标所有者或具有授权权限的运营方。
2. 被授权方：具体人员、团队和可识别的测试账号。
3. 目标范围：域名、IP、端口、应用、环境和第三方依赖。
4. 允许动作：浏览、改包重放、特定漏洞验证、数据读取上限等。
5. 禁止动作：拒绝服务、暴力破解、社会工程、持久化、数据修改/导出等。
6. 时间窗与频率：起止时间、并发/请求频率、维护窗口。
7. 数据处理：生产数据、个人信息、凭据、截图、Evidence 和报告的保管与删除。
8. 紧急联系人与停止条件：告警、业务异常、误触第三方或发现真实敏感数据时如何停测和通报。

如果授权只覆盖某个端口、路径、账号或时间窗，必须额外采用流程/网络控制。RustForge 当前 Scope 只表达 host，不能编码这些更窄限制。

## RustForge 实际强制的技术边界

### 1. ScopePolicy 是唯一目标授权入口

- 项目 Scope 在保存时由后端规范化；代理和 Repeater 不各自维护近似匹配逻辑。
- 没有当前项目、项目不存在、Scope 为空、Scope 无效或目标不匹配时默认拒绝检查/重放。
- 前端的禁用按钮和预检只改善交互，不能作为授权凭据；真正动作会在后端再次校验。
- `projects.target_host` 是显示元数据，真正授权来自 `projects.scope`。

### 2. Scope 是 host-only

允许的输入形态：

- 精确域名：`example.com`
- 域名通配：`*.example.com`
- IPv4：`192.0.2.10`
- IPv6：`2001:db8::10` 或 URL 中的 `[2001:db8::10]`
- 作为输入便利的 HTTP(S) URL 或显式端口；保存时只保留 host

规范化规则：

- 域名转为 IDNA ASCII、小写并去掉尾随点。
- IPv4/IPv6 转为标准文本形式。
- `*.example.com` 同时覆盖 `example.com` 和其子域；IP 不允许通配。
- 端口、路径、query 和 fragment 不参与 Scope 身份，因此 `example.com:8443/path` 不会把授权限制到该端口或路径。
- private、loopback 和 link-local 地址没有隐式许可，只有明确写入 Scope 才命中。

### 3. 代理行为

- Scope 内 HTTPS 才进行 MITM、正文有界捕获、落库和被动规则分析。
- Scope 外 HTTPS CONNECT 盲隧道；Scope 外普通 HTTP 原样透传。两者都不解密/记录/缓冲，也不进入规则引擎。
- 这意味着 Scope 不是防火墙：它阻止 RustForge 检查和主动重放 Scope 外目标，但不会阻止浏览器自身通过代理访问该目标。
- 请求/响应捕获的 wire 与 decoded 缓冲各限制为 1 MiB；截断状态会进入 Traffic、AI、规则、Evidence 和报告。

### 4. Repeater 行为

- 每次发送必须显式携带当前项目和项目内会话。
- 只接受明确的 `http://` / `https://` URL；拒绝 userinfo、无 host、空 authority、反斜杠歧义、控制字符和非法端口。
- URL 授权在创建客户端、解析自定义 Header 和建立 socket 前完成；成功校验返回的解析后 URL 是唯一发包目标。
- 不自动跟随 3xx 重定向，因此不会在未重新校验 Scope 的情况下跳到新 host。
- Scope 拒绝也会形成 `scope_rejected` 审计 run，但不会产生网络连接。
- 允许的网络请求由用户每次点击发送；不存在规则/AI 自动触发 Repeater 的路径。

稳定拒绝码：

| code | 含义 |
|---|---|
| `NO_ACTIVE_PROJECT` | 没有当前项目 |
| `PROJECT_NOT_FOUND` | 指定项目不存在 |
| `EMPTY_SCOPE` | Scope 没有有效条目 |
| `INVALID_SCOPE` | Scope 条目无法规范化 |
| `INVALID_URL` | 主动请求 URL 无效或有歧义 |
| `UNSUPPORTED_SCHEME` | 不是 HTTP(S) |
| `URL_USERINFO` | URL 含 username/password |
| `MISSING_HOST` | URL 缺少 host |
| `INVALID_HOST` | host 语法无效 |
| `OUT_OF_SCOPE` | 规范化 host 未命中 Scope |
| `SCOPE_STORAGE` | 无法安全读取项目授权配置 |

## Scope 之外的敏感数据边界

Scope 只约束目标流量的 MITM/记录与 Repeater 发包，不决定以下外部数据处理是否合法：

- AI provider：用户必须确认授权与数据处理条款允许把脱敏后的流量发给所选 provider。RustForge 默认脱敏并展示最终发送内容，但不能替代组织审批。
- 报告：默认只导出不可变脱敏 Evidence；原始来源片段需要每次在后端原生对话框中确认，导出文件仍可能高度敏感。
- CA：安装 RustForge CA 会使本机信任其签发的站点证书。测试结束后应按组织流程停止代理，并在不再需要时移除信任。
- API Key：Key 存在系统凭据库；不要把 Key、CA 私钥、原始流量或敏感报告放进 issue、日志或提交。

## 人在回路与证据要求

- AI 和被动规则只能创建 pending Finding。
- AnalysisRun 只证明模型调用发生，不能证明漏洞成立。
- Finding 只有在人工接受至少一项具备确认资格的 Traffic/Replay Evidence 后才能变为 confirmed。
- 测试计划的 AI 输出先成为 proposal/diff；人工确认前不改当前计划。
- 报告把建议验证步骤与实际 Evidence 观察分开，不能把计划文字写成已执行复现。

## 测试前检查清单

- [ ] 授权文件仍在有效期内，授权方与目标所有权没有变化。
- [ ] Scope 中每个 host 均在授权清单内；没有用通配符扩大书面范围。
- [ ] 若授权限制端口/路径/账号/时间窗，已配置 Scope 之外的补充控制。
- [ ] 已确认是否允许把数据发送到外部 AI provider；不允许时关闭 AI。
- [ ] 已设定请求频率、禁止动作、停止条件和紧急联系人。
- [ ] 测试账号、环境和数据保留策略已确认。
- [ ] 导出报告前已检查 Evidence 脱敏；敏感导出有独立批准和安全存储位置。

## 发现越界或业务异常时

1. 立即停止代理和 Repeater 操作，不继续“验证一下”。
2. 保存已有的审计 ID、时间和脱敏观察，不扩散原始秘密。
3. 按授权书联系紧急联系人，说明可能受影响的 host、动作与时间窗。
4. 在授权方确认前不要恢复测试，也不要自行扩大 Scope。
