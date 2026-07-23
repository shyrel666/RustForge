# RustForge 签名自动更新设计

**日期：** 2026-07-23  
**状态：** 已实施（待真实发布验证）

## 目标

使用 Tauri 官方 Updater 为 Windows x64 版本提供签名的应用内更新。应用启动后静默检查更新，仅在存在新版本时于顶部 RustForge Logo 右侧（以及关于页品牌旁）显示上箭头按钮；用户确认后完成下载、签名校验与安装。Windows 安装器启动后会退出当前进程并由安装器自动拉起新版本。

同时清理关于页重复的仓库入口：

- 删除第二个重复的 `GitHub` 按钮；
- 将原“官方仓库”按钮改名为 `GitHub`；
- 保留“更新日志”入口。

## 已确认决策

- 更新实现：官方 Tauri v2 Updater。
- 更新源：`shyrel666/RustForge` 的 GitHub Releases。
- 首期平台：Windows x64。
- 检查时机：每次应用启动后静默检查一次。
- 更新入口：仅有更新时显示共享的圆形上箭头按钮；顶部栏与关于页品牌旁共用同一组件。
- 安装方式：用户确认后应用内下载和安装；Windows 由安装器接管重启，应用侧不额外调用 process relaunch。
- 签名密钥：生成新密钥并使用密码保护。
- 私钥位置：`%USERPROFILE%\.tauri\rustforge.key`，禁止进入仓库。
- 关于页保留次要的“重新检查”入口，作为手动兜底。

## 界面与交互

### 更新入口

共享组件 `AppUpdateButton` 出现在：

- 顶部栏品牌文字右侧；
- 关于页品牌标识右侧（沉浸式设置页不显示顶部栏时仍可更新）。

视觉布局：

```text
[ RustForge ] [ ↑（仅发现更新时显示）]
```

更新按钮：

- 使用 Element Plus 上箭头图标；
- 圆形、轻量边框，颜色使用主题强调色；
- 位于品牌文字右侧，不改变现有导航居中布局；
- 从发现更新开始持续显示；下载、安装期间显示进度，失败且仍保留目标更新时用于重试；
- 悬停提示“发现新版本 vX.Y.Z”；
- 下载或安装期间显示进度/加载状态并禁止重复点击；
- 确认对话框打开期间禁止重复确认；
- 支持键盘聚焦，并具有包含目标版本的可访问名称。

### 点击更新

1. 用户点击上箭头；
2. 弹出确认框，显示 `当前版本 → 目标版本` 和可用的发布说明；
3. 用户选择“立即更新”后开始下载；
4. 下载期间显示百分比；服务器未提供总大小时显示不确定进度；
5. 下载完成后校验签名并安装；
6. Windows 安装器启动后退出当前进程，并由安装器自动拉起新版本。

用户取消确认时保留更新按钮，不改变更新状态。

### 关于页

关于卡片操作区调整为：

- `GitHub`：打开仓库首页；
- `更新日志`：打开 Releases；
- `重新检查`：次要按钮，手动触发更新检查。

关于页状态提示：

- `checking`：正在检查更新；
- `available`：发现新版本 vX.Y.Z，并提示可点击品牌旁上箭头更新；
- `latest`：当前已是最新版本；
- `error`：检查失败，可点击“重新检查”；
- `downloading`：显示下载进度；
- `installing`：显示“正在安装，完成后将自动重启”。

自动静默检查在无更新或失败时不弹消息；手动检查才显示成功或错误反馈。

## 更新状态模块

新增单一更新状态模块，供 `AppShell`、`AppTopbar`、`AppUpdateButton` 和 `SettingsView` 共用。

状态：

```ts
type AppUpdateStatus =
  | "idle"
  | "checking"
  | "latest"
  | "available"
  | "downloading"
  | "installing"
  | "error";
```

公开数据：

- 当前状态；
- 当前版本；
- 目标版本；
- 发布说明；
- 已下载字节；
- 总字节（可能为空）；
- 下载百分比（总字节可用时）；
- 最近错误；
- 是否已完成本次启动的自动检查。

公开操作：

- `checkForUpdates({ automatic?: boolean; silent?: boolean })`；
- `downloadAndInstall()`；
- `resetError()`。

规则：

- 同一时刻只允许一个检查或安装任务；
- 本次启动的自动检查只执行一次；
- 手动检查允许在自动检查后再次执行；
- `check()` 返回 `null` 时进入 `latest`；
- Tauri `ReleaseNotFound`（无有效 `latest.json`）按无更新处理；
- 下载进度根据 Updater 的 `Started / Progress / Finished` 事件累计；
- 安装失败时保留目标更新对象，以便用户重试；
- Windows 安装器接管重启，不单独处理 process relaunch 失败。

## Tauri 集成

### 依赖

前端：

- `@tauri-apps/plugin-updater`

Rust：

- `tauri-plugin-updater`，仅桌面目标。

### 初始化

在 Tauri Builder 注册 updater 插件。Updater 使用配置文件中的端点和公钥。

### Capability

主窗口增加：

- `updater:default`

### 配置

`tauri.conf.json`：

- `bundle.createUpdaterArtifacts: true`；
- Updater 公钥为生成的 `.pub` 文件内容；
- endpoint：

```text
https://github.com/shyrel666/RustForge/releases/latest/download/latest.json
```

生产环境仅允许 HTTPS。

## 签名密钥

密钥由 Tauri CLI 生成：

```powershell
pnpm tauri signer generate --write-keys "$HOME/.tauri/rustforge.key"
```

生成过程由用户在终端输入密码。

文件：

- `rustforge.key`：加密私钥，只保存在用户目录；
- `rustforge.key.pub`：公钥，内容写入 `tauri.conf.json`。

私钥和密码不得写入仓库、文档、日志或聊天。私钥应额外离线备份；丢失私钥后无法向已安装版本发布可验证的新更新。

## GitHub Actions 发布

新增 Windows 发布工作流：

- 触发：推送 `v*` 标签；
- Runner：`windows-latest`；
- 安装 Node、pnpm 与 Rust stable；
- 安装前端依赖；
- 校验标签版本与 `package.json` / `Cargo.toml` / `tauri.conf.json` 一致；
- 使用 `tauri-apps/tauri-action` 构建并创建 GitHub Release；
- 生成 Windows 安装包、Updater artifact、签名和 `latest.json`；
- Release 默认非草稿、非预发布。

工作流环境变量：

- `GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}`;
- `TAURI_SIGNING_PRIVATE_KEY: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}`;
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY_PASSWORD }}`。

由于当前开发环境没有 GitHub CLI，Secrets 由用户在仓库 Settings → Secrets and variables → Actions 中手动添加。

发布前必须保证以下版本一致：

- `package.json`；
- `src-tauri/Cargo.toml`；
- `src-tauri/tauri.conf.json`；
- Git 标签 `vX.Y.Z`。

## 错误处理

- 启动静默检查失败：记录状态，不弹出消息，不影响应用其他功能；
- 手动检查失败：显示可读错误并允许重试；
- 无可用 Release / Tauri `ReleaseNotFound`：按无更新处理；
- 下载中断：回到可重试状态并保留版本信息；
- 签名校验失败：停止安装，明确提示更新包校验失败；
- 安装失败：不退出当前进程，保留更新按钮；
- 开发环境检查失败：静默处理，不阻塞 `tauri dev`。

## 测试与验证

### 自动验证

- 更新状态与并发保护；
- 下载进度累计与百分比；
- 无总大小时的不确定进度；
- 检查无更新、检查失败、下载失败与重试；
- `ReleaseNotFound` 识别；
- 前端 TypeScript 检查与生产构建；
- Rust `cargo check`；
- Tauri Capability 与配置 Schema。

### 发布验证

1. 使用测试标签构建签名的 Windows Release；
2. 在较低版本安装包中启动应用；
3. 确认启动无弹窗且顶部/关于页出现更新按钮；
4. 确认取消后按钮保留；
5. 再次点击并完成下载、签名校验、安装；
6. 确认安装器拉起后的版本号更新，按钮消失；
7. 确认关于页仓库按钮只剩一个 `GitHub`。

## 非目标

- macOS 或 Linux 自动更新；
- 强制更新；
- 后台无确认自动安装；
- 自建更新服务器；
- 增量更新；
- 自动配置 GitHub Secrets；
- 应用商店渠道更新。
