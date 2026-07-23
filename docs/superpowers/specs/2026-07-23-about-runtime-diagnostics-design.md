# About 页「运行环境」诊断卡

**日期:** 2026-07-23  
**状态:** 已批准（方案 1）

## 问题

设置 → 关于 仅有版本卡与免责脚注，主内容区下方空白过大，缺少对用户有用的信息。

## 目标

从用户视角补一块轻量、可操作的运行环境信息：出问题能自查，提 Issue 能一键带上环境摘要。

## 方案

在版本卡与页脚之间增加 **「运行环境」** 卡片（复用 `rf-card`）。

### 展示字段

| 行 | 展示 | 数据来源 |
|---|---|---|
| 应用 | RustForge `vX.Y.Z` | `getVersion` |
| 系统 | 如 `Windows · x64` | 新 command `get_runtime_info`（`OS` / `ARCH`） |
| 代理 | 未运行 / 运行中 · 端口 | `proxy_status`；未运行时端口回退 `settings.proxy_port` |
| CA 证书 | 已信任 / 未安装 | `get_ca_info.trusted` |

### 操作

- **复制诊断信息**：固定模板纯文本写入剪贴板（含上表 + 数据目录路径，不含 API Key / 私钥 / 请求体）
- **打开数据目录**：新 command `reveal_app_data_dir`，资源管理器打开 `app_data_dir`

### 非目标

- 不做自动上报、实时轮询、完整运维面板
- 不做一键跳转修复（故障中心）
- 不展示依赖清单 / 更新日志正文

## 实现边界

- 进 About Tab 时拉取一次（`watch` / 首次进入）
- 后端尽量复用现有 command；仅新增 `get_runtime_info`、`reveal_app_data_dir`
- UI 仅改 `SettingsView` 关于区 + `tauri.ts` 类型封装

## 成功标准

- 关于页空白明显收窄
- 用户可复制一段可粘贴到 Issue 的诊断文本
- 可打开本地数据目录排查证书 / 数据库
