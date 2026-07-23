<div align="center">

# 🛡️ RustForge

**面向渗透初学者的 AI 引导式渗透测试桌面应用**

*An AI-guided penetration-testing companion for beginners — capture → analyze → guide → verify → report.*

![Platform](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows&logoColor=white)
![Rust](https://img.shields.io/badge/Rust-1.86+-CE422B?logo=rust&logoColor=white)
![Tauri](https://img.shields.io/badge/Tauri-2-FFC131?logo=tauri&logoColor=black)
![Vue](https://img.shields.io/badge/Vue-3-4FC08D?logo=vuedotjs&logoColor=white)
![AI](https://img.shields.io/badge/AI-BYO%20Key%20·%20OpenAI%20兼容-8A2BE2)
![Status](https://img.shields.io/badge/progress-Phase%200–5%20完成-2ea44f)

</div>

> ## ⚠️ 授权与免责声明
> RustForge **仅用于对已获书面授权的目标进行安全测试与学习**。对未授权的系统进行拦截、探测或攻击可能违反法律，一切后果由使用者自行承担。
> 首次启动会强制阅读并确认授权声明；**只有加入项目 Scope 白名单的域名才会被拦截**；AI 只做分析与建议，**绝不自动向目标发起攻击**。

RustForge 面向「已获授权但不知从何下手」的渗透初学者：内置 MITM 代理抓取目标流量，云端 AI（**用户自带 Key**）解释接口、标记可疑点，并动态生成一棵**渗透任务树**一步步引导你操作；每个结论都附带 OWASP/CWE 知识、置信度与**人工验证步骤**，配合内置 Repeater 手动复核，最后一键导出学习报告。

---

## ✨ 核心特性

| 模块 | 能力 |
|------|------|
| 🕸️ **MITM 代理** | HTTPS 拦截、CA 证书生成与一键安装引导、Scope 白名单过滤、连通性自检 |
| 📊 **流量工作台** | 请求/响应表格，方法·状态·类型过滤 + 搜索，详情查看器，**大流量分页加载** |
| 🧪 **被动规则引擎** | 14 条内置规则自动打标（SQL 报错、堆栈泄露、敏感参数、明文口令、JWT、Cookie 标志缺失…），AI 分析前的本地初筛 |
| 🤖 **AI 分析引擎** | 选中请求 → 接口用途 / 可疑参数 / 漏洞假设（**类型 + OWASP + CWE + 置信度 + 推理 + 验证步骤**）；提示词模板可定制，凭据类头自动脱敏 |
| 🌳 **渗透任务树** | AI 基于流量摘要生成引导树；每个节点回答四问（做什么/为什么/怎么做/怎样算完成）；**下一步 / 展开子任务 / 换个思路 / 手动标记状态**；与「发现」双向关联；vue-flow 可视化 |
| 📚 **知识库** | OWASP Top 10 (2021) + 常见 CWE 中文卡片（原理 / 危害 / 成因 / 修复建议） |
| 🔁 **Repeater** | 手动改包重发，观察响应做人工验证（忽略证书错误、不自动跟随重定向） |
| 🎯 **发现管理** | 待验证 / 已确认 / 误报 状态流转，按来源(AI/规则)·严重度·置信度筛选 |
| 📄 **学习报告** | 一键导出 Markdown：发现列表（含复现与修复建议）+ 渗透过程时间线 + 任务树概览 |
| ⚙️ **设置中心** | BYO API Key / Base URL / 模型、代理端口、Scope、AI 全局开关、**token 用量与成本估算** |

## 🔒 设计红线

- **人在回路**：AI 只做分析、解释、建议，绝不自动对目标发送攻击载荷；所有验证动作由你手动执行。
- **误报素养**：每个 AI/规则结论都带置信度 + 推理过程 + 手动验证步骤；发现默认「待验证」，人工复核后才可标记确认。
- **授权优先**：启动授权声明 + Scope 白名单 + 隐私开关（可全局禁用 AI，流量不外发）。

## 🧭 工作闭环

```
抓包(MITM) ─▶ 被动规则初筛 + AI 分析 ─▶ 渗透任务树引导 ─▶ Repeater 手动验证 ─▶ 发现确认 ─▶ 学习报告
```

## 🏗️ 架构

```
┌─────────────────────────────────────────────────────┐
│  Tauri 2 前端 (Vue 3 + Element Plus + Pinia)          │
│  流量表格 / 详情 / Repeater / 任务树(vue-flow) /       │
│  发现 + 知识卡片 / 报告 / 设置                          │
├──────────────── Tauri Commands / Events ─────────────┤
│  Rust 后端 (tokio 异步)                                │
│  ├─ proxy   : hudsucker(hyper+rustls+rcgen) MITM       │
│  ├─ rules   : 被动规则引擎（regex/启发式）              │
│  ├─ ai      : LLM 客户端 + 提示词 + 分析器 + 任务树规划 │
│  ├─ tree    : 任务树状态机                              │
│  ├─ knowledge / report : 知识卡片 + Markdown 报告       │
│  └─ storage : rusqlite（项目/流量/发现/树/设置）        │
└─────────────────────────────────────────────────────┘
```

## 🚀 快速开始

**前置依赖**
- [Node.js](https://nodejs.org/) 18+ 与 [pnpm](https://pnpm.io/)
- [Rust](https://www.rust-lang.org/) 1.86+（stable 工具链）
- Windows 10/11（自带 WebView2 运行时）
- 其余 Tauri 前置见官方文档：<https://v2.tauri.app/start/prerequisites/>

**开发运行**
```bash
pnpm install
pnpm tauri dev
```

**打包（生成安装包）**
```bash
pnpm tauri build   # 产物在 src-tauri/target/release/bundle/
```

**首次使用**
1. 阅读并确认**授权声明**；
2. 在「设置」填入 API Key（支持 OpenAI 兼容接口，见下表）；
3. 新建项目，把**已授权的目标域名**加入 Scope 白名单；
4. 点「证书引导」安装 CA，把浏览器/系统代理指向 `127.0.0.1:8080`；
5. 启动代理 → 浏览目标 → 流量实时出现 → 选中请求做 AI 分析 / 生成任务树 → Repeater 验证 → 导出报告。

## 🧠 支持的模型（OpenAI 兼容，自带 Key）

| 服务 | Base URL | 示例模型 |
|------|----------|----------|
| DeepSeek | `https://api.deepseek.com` | `deepseek-chat` |
| Kimi (Moonshot) | `https://api.moonshot.cn/v1` | `moonshot-v1-8k` |
| 通义千问 | `https://dashscope.aliyuncs.com/compatible-mode/v1` | `qwen-plus` |
| OpenRouter | `https://openrouter.ai/api/v1` | 任意兼容模型 |
| OpenAI | `https://api.openai.com/v1` | `gpt-4o-mini` |

> 也可在设置中**全局禁用 AI**，此时任何数据都不会外发。

## 📂 目录结构

```
RustForge/
├─ src/                 Vue 前端
│  ├─ views/            Traffic / Repeater / TaskTree / Findings / Settings
│  ├─ components/       AnalysisPanel / KnowledgeCard / ScopeDialog / ...
│  ├─ stores/           traffic / findings / tree / repeater / settings / project
│  └─ api/tauri.ts      invoke 封装 + 事件订阅
├─ src-tauri/           Rust 后端
│  └─ src/
│     ├─ proxy/         MITM 代理（ca / interceptor）
│     ├─ rules/         被动规则引擎（engine / builtin）
│     ├─ ai/            client / prompts / analyzer / planner / digest
│     ├─ tree/          任务树模型 + 状态机
│     ├─ knowledge/     OWASP/CWE 知识卡片
│     ├─ report.rs      Markdown 报告
│     ├─ storage/       rusqlite（schema / models）
│     └─ commands.rs    暴露给前端的全部 Tauri commands
└─ docs/                授权声明 + 各阶段完成说明（PHASE1–5）
```

## 🗺️ 路线图

| 阶段 | 内容 | 状态 |
|------|------|------|
| Phase 0 | 工程骨架、设置、项目管理、授权声明 | ✅ |
| Phase 1 | MITM 代理（HTTPS 拦截、CA 引导）、流量表格与详情 | ✅ |
| Phase 2 | AI 请求分析（假设+OWASP+置信度+验证步骤）、被动规则引擎 | ✅ |
| Phase 3 | 渗透任务树（AI 规划、状态机、vue-flow 引导） | ✅ |
| Phase 4 | OWASP/CWE 知识卡片、Repeater、Markdown 学习报告 | ✅ |
| Phase 5 | token 用量统计与成本、大流量分页、会话恢复、打包 | ✅ |

> 各阶段的交付说明、测试与验收见 [`docs/PHASE1.md`](docs/PHASE1.md) … [`docs/PHASE5.md`](docs/PHASE5.md)。

## 🙌 灵感与致谢

RustForge 的设计参考并致敬以下优秀项目：

- **[Burp Suite](https://portswigger.net/burp) / [Caido](https://caido.io/)** — 代理与流量工作台、Repeater 交互范式
- **[burpgpt](https://github.com/aress31/burpgpt)** — LLM 辅助请求分析与提示词模板注入
- **[PentestGPT](https://github.com/GreyDGL/PentestGPT)** — 渗透任务树（PTT）与引导式推进
- **[Deciduous](https://github.com/rpetrich/deciduous)** — 攻击树可视化思路
- **[Strix](https://github.com/usestrix/strix) / [Vulnhuntr](https://github.com/protectai/vulnhuntr)** — 发现报告结构与漏洞讲解
- **[hackingBuddyGPT](https://github.com/ipa-lab/hackingBuddyGPT)** — 会话化 AI 渗透助手理念

## ⚖️ 许可

本项目**仅用于授权测试与安全教育**，请勿用于任何未授权场景。

> 尚未选定开源许可协议（建议 MIT）；在明确选定前，默认保留所有权利。
