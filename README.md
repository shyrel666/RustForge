# RustForge

面向渗透测试初学者的 AI 引导式桌面应用：内置 MITM 代理抓取授权目标流量，云端 AI（用户自带 Key）分析流量、讲解可疑点，并动态生成**渗透任务树**一步步引导你完成测试。

> ⚖️ **仅用于学习与授权测试**。对未授权目标进行探测/攻击违反法律，后果自负。

## 功能路线

| 阶段 | 内容 | 状态 |
|------|------|------|
| Phase 0 | 工程骨架、设置（API Key/代理端口）、项目管理、授权声明 | ✅ |
| Phase 1 | MITM 代理（HTTPS 拦截、CA 证书引导）、流量表格与详情 | ✅ |
| Phase 2 | AI 请求分析（漏洞假设 + OWASP 分类 + 置信度 + 验证步骤）、被动规则引擎 | ✅ |
| Phase 3 | 渗透任务树（AI 规划、状态流转、图形化引导） | ⬜ |
| Phase 4 | OWASP/CWE 知识卡片、Repeater、Markdown 学习报告 | ⬜ |
| Phase 5 | 会话回放、性能优化、token 用量统计、打包 | ⬜ |

## 设计红线

- **人在回路**：AI 只做分析、解释、建议，绝不自动对目标发送攻击载荷
- **误报素养**：每个 AI 结论带置信度 + 推理过程 + 手动验证步骤
- **授权优先**：首次启动强制确认授权声明；仅拦截项目 Scope 白名单内的流量

## 技术栈

- 后端：Rust + Tauri 2 + tokio + rusqlite（SQLite，bundled）
- 代理：hudsucker（hyper + rustls + rcgen）（Phase 1）
- 前端：Vue 3 + Vite + Element Plus + Pinia + vue-router

## 开发

```bash
pnpm install
pnpm tauri dev
```

## 目录结构

```
src-tauri/   Rust 后端（代理 / AI / 任务树 / 存储 / Tauri commands）
src/         Vue 前端（视图 / 组件 / stores / API 封装）
docs/        授权声明模板、提示词模板说明
scripts/     工具脚本（图标生成等）
```
