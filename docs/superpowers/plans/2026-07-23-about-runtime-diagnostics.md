# About Runtime Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a user-facing「运行环境」card on Settings → About with copy diagnostics and open data dir.

**Architecture:** Two thin Tauri commands expose OS/arch/app_data_dir and reveal the folder; About tab loads version + proxy + CA + runtime in parallel and renders a read-only card with two actions.

**Tech Stack:** Tauri 2 (Rust commands), Vue 3 + Element Plus, existing `proxy_status` / `get_ca_info`.

---

### Task 1: Backend commands

**Files:**
- Modify: `src-tauri/src/commands.rs`
- Modify: `src-tauri/src/lib.rs`

- [x] **Step 1:** Add `RuntimeInfo { os, arch, app_data_dir }` and `get_runtime_info`
- [x] **Step 2:** Add `reveal_app_data_dir` (open folder; mirror `reveal_ca_cert` platform branches)
- [x] **Step 3:** Register both in `generate_handler!`

### Task 2: Frontend API

**Files:**
- Modify: `src/api/tauri.ts`

- [x] **Step 1:** Export `RuntimeInfo`, `getRuntimeInfo`, `revealAppDataDir`

### Task 3: About UI

**Files:**
- Modify: `src/views/SettingsView.vue`

- [x] **Step 1:** Load diagnostics when About tab is shown
- [x] **Step 2:** Render env card + copy / open-dir actions + styles
- [x] **Step 3:** Verify TypeScript/build; smoke-check About tab

---

## Spec self-review

- No TBD placeholders
- Scope matches approved design (scheme 1 only)
- Sensitive data excluded from copy template
