<div align="center">

# RustForge

**面向已授权目标、人在回路的证据驱动安全测试工作台**

*Capture → hypothesize → plan → replay → evidence → review → report.*

![Platform](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows&logoColor=white)
![Rust](https://img.shields.io/badge/Rust-1.88+-CE422B?logo=rust&logoColor=white)
![Tauri](https://img.shields.io/badge/Tauri-2-FFC131?logo=tauri&logoColor=black)
![Vue](https://img.shields.io/badge/Vue-3-4FC08D?logo=vuedotjs&logoColor=white)
![AI](https://img.shields.io/badge/AI-BYO%20Key%20·%20OpenAI%20兼容-8A2BE2)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

</div>

> ## 授权与免责声明
>
> RustForge 仅用于对已获得明确书面授权的目标进行安全测试与学习。首次启动会要求确认授权声明；AI 只能从版本化安全模板中选择检查，不能生成 URL、方法、Header、正文或 payload。目标请求由 Rust 后端同时执行运行契约、`AssessmentPolicy` 与 `ScopePolicy`；只有确定性安全验证器可以自动确认，模型输出本身永远不能确认漏洞。Scope 和运行契约是技术保护边界，不是法律授权的替代品。详细要求见 [docs/AUTHORIZATION.md](docs/AUTHORIZATION.md)。

RustForge 把 URL 起扫、只读发现、有界 AI 规划、后端安全模板、确定性验证、MITM 流量、Repeater、Evidence 和脱敏报告串成一条可追溯闭环。用户确认一次精确运行契约后，后台评估会给出“已确认、疑似、未观察到、覆盖缺口”四类结果；它不是通用利用器，也不向模型开放任意网络能力。

## 当前能力

| 模块 | 当前实现 |
|---|---|
| **授权与代理** | 项目级 host-only Scope；域名/IDN/IP 规范化；Scope 外 HTTPS 不解密，Scope 外流量不记录；CA 私钥安全落盘 |
| **有界流量采集** | 请求与响应按帧转发；线缆捕获和解压后捕获各限制为 1 MiB；支持 gzip/deflate/br；保存实际 wire size、captured size、截断和解码状态；重复 Header 不合并 |
| **被动规则 v1** | 14 条内置声明式规则在有界后台队列执行；包、规则、标准引用和命中证据均带版本；相同问题按稳定指纹去重；中危及以上只生成 pending Finding |
| **AI 上下文防火墙** | API Key 存系统凭据库；发送前展示最终上下文；URL/Header/JSON/表单/multipart/高熵秘密结构化脱敏；预览哈希绑定 provider、模型、提示词、policy 和 Schema；模型输出经后端校验 |
| **版本化标准** | 离线知识包固定到 OWASP Top 10 2021/2025、OWASP API Top 10 2023、ASVS 5.0.0、WSTG 4.2、CWE 4.20；未知版本或编号不会被猜测映射 |
| **AI 非破坏式评估** | 从 URL 开始发现；AI 每轮只选择不透明 endpoint 与版本化模板；最多三轮、每轮 12 项；后端固定并发 1、只允许 GET/HEAD/OPTIONS、精确 origin、危险路径拦截、无正文、无重定向、硬预算与停止条件 |
| **身份 A/B** | 只允许四种鉴权 Header；秘密值仅存系统凭据库，SQLite、Replay、事件、AI 上下文和报告只保存 profile 占位符；A/B 相同秘密会在运行前拒绝 |
| **Finding 与 Evidence** | AI/规则结果保持 pending；版本化安全验证器可在完整证据满足阈值时原子接受 Evidence 并确认 Finding；人工拒绝不会被自动复活，模型 Evidence 永远不能自动确认 |
| **Repeater** | 项目内多会话、TLS 策略、不可变发送历史、失败/越界审计、重启中断恢复、分页和 run diff；每次发送均由用户触发且在建连前重新校验 Scope |
| **旧测试计划** | 原 proposal/revision/task tree 数据和 API 保留一个兼容版本，但从主导航隐藏，不接收 Assessment 写入，也不再被描述为已执行测试 |
| **证据化报告 v3** | 同时导出 Markdown 与 JSON；区分 confirmed/suspected/not observed/coverage gap，附契约、模板、AI round、预算、身份标签和时间线；默认只使用脱敏快照 |
| **桌面工作台** | 流量窗口分页、项目恢复、token 用量与趋势、本地成本估算、运行诊断、签名更新客户端和发布工作流 |

## 不做什么

- 不执行 SQL/命令注入、目录穿越、SSRF、上传、爆破、DoS、表单/POST 业务逻辑、浏览器脚本或任意 payload。
- 不因为规则命中或模型输出而自动把 Finding 标为 confirmed；自动确认权只属于版本固定、观察阈值确定的安全验证器。
- 不把前端按钮状态当作授权；所有目标请求仍由 Rust 后端复核 Scope。
- 不执行规则包中的脚本、文件、进程或网络动作；规则只能读取已捕获的有界 HTTP 字段。
- 当前不记录 WebSocket 消息，也不提供 SSE/gRPC/GraphQL 专用语义、自动重定向或任意自主 agent 工作流。

## 证据闭环

```text
URL + Scope + 书面授权确认
              │
              ▼
  只读发现 ─▶ AI 模板选择 DSL ─▶ 后端策略/预算复核
                                      │
                                      ▼
                      固定模板请求 ─▶ 确定性安全验证器
                                      │
                     ┌────────────────┼────────────────┐
                     ▼                ▼                ▼
               confirmed         suspected      not observed / gap
                     │
                     ▼
        脱敏 Evidence + Finding 事件 ─▶ Markdown + JSON 报告
```

AnalysisRun 可以证明“模型调用与校验发生过”，但不能证明漏洞存在；没有真实响应的 Traffic 也不能支撑确认。具体资格规则见 [数据模型](docs/architecture/data-model.md) 和 [安全边界](docs/architecture/security-boundaries.md)。

## 架构

```text
┌─────────────────────────────────────────────────────────────┐
│ Tauri 2 前端：Vue 3 + Element Plus + Pinia + vue-flow       │
│ AI 评估 / 流量 / Repeater / Findings / Evidence / 报告     │
├──────────────────── Tauri Commands / Events ────────────────┤
│ Rust 后端                                                    │
│ authorization  共享 ScopePolicy                             │
│ proxy          hudsucker MITM + 有界流式捕获                 │
│ rules          声明式规则包 + 后台 worker + 稳定指纹         │
│ ai             脱敏上下文 + 提示词版本 + 输出校验            │
│ assessment     契约 / 发现 / DSL / 模板 / 策略 / 验证器      │
│ replay         手动与评估隔离的 session / attempt / run      │
│ evidence       快照、人工/验证器接受和 Finding 事件          │
│ tree           隐藏兼容的旧测试计划模块                      │
│ knowledge      版本化离线标准包                              │
│ report         Evidence Report Schema v3                     │
│ storage        SQLite v3 + 真实迁移/外键/触发器约束           │
└─────────────────────────────────────────────────────────────┘
```

架构事实以以下文档和对应源码为准：

- [数据模型与持久化约束](docs/architecture/data-model.md)
- [安全边界与失败策略](docs/architecture/security-boundaries.md)
- [声明式规则包 v1](docs/architecture/rule-pack-v1.md)
- [现代化安全红线 ADR](docs/architecture/0001-modernization-guardrails.md)
- [规则 v2 影子评测记录](docs/architecture/rule-shadow-evaluation.md)

## 快速开始

### 前置依赖

- [Node.js](https://nodejs.org/) 22.22.3 与 [pnpm](https://pnpm.io/) 9.15.9（仓库固定版本）
- [Rust](https://www.rust-lang.org/) 1.88+（`rust-toolchain.toml` 固定日常工具链）
- Windows 10/11 与 WebView2
- 其余环境要求见 [Tauri 2 prerequisites](https://v2.tauri.app/start/prerequisites/)

### 开发运行

```bash
pnpm install
pnpm tauri dev
```

### 提交前质量门禁

```bash
pnpm check
cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml --all-targets
cargo +1.88.0 check --manifest-path src-tauri/Cargo.toml --all-targets
```

### 打包

```bash
pnpm tauri build
```

安装包位于 `src-tauri/target/release/bundle/`。签名自动更新还需要仓库外的签名私钥与 GitHub Secrets；私钥不得提交到仓库。

### 首次使用

1. 阅读并确认授权声明。
2. 新建项目，把书面授权覆盖的 host 加入 Scope。
3. 在“AI 评估”填写起始 URL；可选配置身份 A/B、资源归属、额外排除路径和预算。
4. 如需 AI，在设置中添加 OpenAI 兼容 provider；API Key 和身份值写入系统凭据库，而非 SQLite 或前端持久状态。
5. 审阅精确 origin、只读方法、请求/速率上限、身份标签、模板 registry 与 AI 数据披露，确认书面授权后启动。
6. 在运行页查看发现、规划、执行、验证时间线；发现异常可立即取消，部分结果仍会保存。
7. 在结果页区分已确认、疑似、未观察到和覆盖缺口，并查看脱敏 Replay/Evidence。
8. 如需手工验证，仍可使用独立 Repeater；Assessment 的内部 session 不会暴露给手动 API。
9. 按本次 run 或项目累计导出默认脱敏的 Markdown/JSON 报告。

设置页的 provider 预设只是可编辑的便利值。模型名称和服务可用性会变化，应使用 provider 的 `/models` 返回或其官方控制台确认；RustForge 只要求 OpenAI 兼容接口，不把某个外部模型视为架构依赖。

## 目录结构

```text
RustForge/
├─ src/                         Vue 前端
│  ├─ views/                    Assessment / Traffic / Repeater / Findings / Settings
│  ├─ components/               AI 预览 / Evidence / Replay diff / 旧计划兼容
│  ├─ stores/                   assessment / project / traffic / replay / findings
│  └─ api/tauri.ts              IPC 类型与 invoke 封装
├─ src-tauri/
│  ├─ src/authorization/        ScopePolicy
│  ├─ src/proxy/                MITM、CA、有界捕获
│  ├─ src/rules/                规则 schema、loader、engine、worker、内置包
│  ├─ src/ai/                   上下文、脱敏、提示词、校验、分析与规划
│  ├─ src/assessment/           运行契约、发现、策略、AI DSL、模板与验证
│  ├─ src/replay/               手动/评估隔离的会话、run 与 diff
│  ├─ src/evidence/             Evidence 与 Finding 复核服务
│  ├─ src/tree/                 隐藏兼容的版本化测试计划
│  ├─ src/knowledge/            版本化离线标准包
│  ├─ src/report.rs             Evidence Report Schema v3
│  └─ src/storage/              SQLite v3 schema、迁移框架与模型
└─ docs/                        授权、阶段说明、架构与实施记录
```

## 阶段说明

| 阶段 | 当前对应能力 | 状态 |
|---|---|---|
| Phase 0 | 工程骨架、项目、设置、授权确认与质量门禁 | 完成 |
| Phase 1 | Scope、MITM、CA、有界流量采集与工作台 | 完成 |
| Phase 2 | AI 上下文防火墙、版本化标准与声明式规则 | 完成 |
| Phase 3 | 证据驱动、可增量合并的版本化测试计划 | 完成 |
| Phase 4 | Repeater、Evidence、人工复核与报告闭环 | 完成 |
| Phase 5 | 分页、用量、恢复、桌面发布与诊断 | 完成；签名 Release E2E 需外部 Secrets |
| Phase 6 | AI 引导式非破坏评估、版本化验证器与报告 v3 | 完成 |

详见 [PHASE1](docs/PHASE1.md)、[PHASE2](docs/PHASE2.md)、[PHASE3](docs/PHASE3.md)、[PHASE4](docs/PHASE4.md)、[PHASE5](docs/PHASE5.md) 和 [PHASE6](docs/PHASE6.md)。协议、过滤和受限插件增强仍是独立 backlog。

## 参考项目定位

> 核查日期：2026-07-29。以下链接和定位按当日官方文档或仓库 README 复核；再次据此做架构决策前必须重新核查。参考不代表依赖、兼容或复制其自主执行模型。

| 项目 | RustForge 采用的定位 | 明确不继承的部分 |
|---|---|---|
| [Burp Suite HTTP history](https://portswigger.net/burp/documentation/desktop/tools/proxy/http-history) / [Repeater](https://portswigger.net/burp/documentation/desktop/tools/repeater) | 持续跟踪代理历史、请求详情、人工重放和对比交互基准 | 不据此引入自动扫描或 Burp AT 式自主发送 |
| [Caido HTTP History](https://docs.caido.io/app/quickstart/http_history.html) / [Replay](https://docs.caido.io/app/guides/replay_resending) | 轻量流量工作台、历史到 Replay 的衔接和请求编辑体验基准 | 不照搬 Automate 或插件执行能力 |
| [burpgpt](https://github.com/aress31/burpgpt) | 项目早期“对代理流量做 LLM 辅助分析”的历史灵感 | 社区版当前已声明不再维护；RustForge 的凭据、脱敏、预览、哈希绑定和校验架构不以它为依据 |
| [PentestGPT](https://github.com/GreyDGL/PentestGPT) / [USENIX 论文](https://www.usenix.org/system/files/usenixsecurity24-deng.pdf) | 保留把复杂评估拆成有界轮次与可解释检查的思想 | 不继承通用自主 agent；RustForge 的模型只能选择后端版本化模板，不能编写或执行动作 |
| [Deciduous](https://github.com/rpetrich/deciduous) | adverse-scenario 图形表达和可视化启发 | 当前 RustForge 只有 parent + prerequisite，不宣称实现 AND/OR 攻击树或决策树语义 |
| [Strix](https://github.com/usestrix/strix) | 借鉴真实验证、执行轨迹和风险表达的重要性 | 不引入自主 agent、自动 PoC、自动利用或自动修复 |
| [Vulnhuntr](https://github.com/protectai/vulnhuntr) | 仅作为未来“源码辅助模式”中调用链上下文补全的参考 | 不并入当前黑盒 HTTP 流程，也不复制其 Python-only 和有限漏洞类别边界 |
| [hackingBuddyGPT](https://github.com/ipa-lab/hackingBuddyGPT) | 仅参考能力边界、轮次/执行预算和可审计日志 | 不允许模型执行本机或远程 shell，不引入自主提权/攻击循环 |

历史起步方案保留在 `docs/superpowers/plans/` 作为项目演进记录；其中的旧术语和旧参考定位不代表当前架构。

## 许可

本项目采用 [MIT License](LICENSE)。开源许可只授予软件使用权，不授予测试任何第三方系统的权限。
