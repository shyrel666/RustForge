# 授权测试声明（模板）

在使用 RustForge 对任何目标进行测试前，请确保你已获得**书面授权**。以下为授权书应包含的最小要素，供参考：

## 授权书要素

1. **授权方**：目标系统的所有者或合法运营方（公司盖章/负责人签字）
2. **被授权方**：执行测试的人员姓名/团队
3. **授权范围**：
   - 目标域名 / IP / 应用清单（明确列出，超出范围即越权）
   - 允许的测试类型（如：Web 漏洞测试、是否允许暴力破解、是否允许社会工程学）
   - 禁止行为（如：拒绝服务测试、数据导出、修改生产数据）
4. **授权时间窗**：起止日期
5. **免责与保密条款**：测试中发现的数据的处理方式
6. **紧急联系人**：测试过程中触发告警时的沟通渠道

## 常见合法练习环境（无需额外授权）

- [PortSwigger Web Security Academy](https://portswigger.net/web-security)（免费靶场）
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)（本地部署）
- DVWA / Pikachu / Vulhub（本地靶场）
- HackTheBox / TryHackMe（平台授权范围内）
- 各大厂商 SRC 的漏洞赏金计划（严格遵守其范围与规则）

## 法律提示

- 《中华人民共和国网络安全法》第二十七条：不得从事非法侵入他人网络、干扰他人网络正常功能、窃取网络数据等危害网络安全的活动。
- 《刑法》第二百八十五条/二百八十六条：非法侵入计算机信息系统罪、破坏计算机信息系统罪。
- 即使是"学习目的"，对未授权目标的扫描与攻击也可能构成违法。

## RustForge 的技术授权边界

- 项目 Scope 由 Rust 后端统一规范化和判定，代理与 Repeater 共用同一个 `ScopePolicy`。
- 没有当前项目、项目不存在、Scope 为空或目标未命中时默认拒绝，不依赖前端提示放行。
- Scope 是 host-only：可填写域名、IPv4、IPv6 或 `*.example.com`；粘贴 URL 和显式端口仅作为输入便利，端口不扩大授权范围。
- 域名按 IDNA 转为 ASCII，并统一处理大小写和尾随点。`*.example.com` 同时覆盖 apex 与其子域。
- Repeater 只接受明确的 `http://` / `https://` URL，拒绝 userinfo、缺失 host、非法端口和歧义 URL；不自动跟随重定向。
- 私网、loopback、链路本地地址不会自动获准，只有被项目 Scope 明确列出时才可拦截或重放。
- Repeater 编辑器先调用无网络预检来禁用越界发送；真正发包时后端会再次校验，避免把 UI 状态当作授权凭据。

稳定拒绝码包括：`NO_ACTIVE_PROJECT`、`PROJECT_NOT_FOUND`、`EMPTY_SCOPE`、
`INVALID_SCOPE`、`INVALID_URL`、`UNSUPPORTED_SCHEME`、`URL_USERINFO`、
`MISSING_HOST`、`INVALID_HOST`、`OUT_OF_SCOPE`。
