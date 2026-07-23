# RustForge Desktop UI Redesign Design

**Date:** 2026-07-23  
**Status:** Approved for implementation

## Goal

Upgrade the desktop frontend from a default Element Plus dark admin look to a **modern product shell + professional high-density tool workspace**.

## Locked decisions

| Decision | Choice |
|----------|--------|
| Aesthetic | Hybrid: productized shell, dense work areas |
| Tech | Custom shell + Element Plus for tables/forms/dialogs |
| Window chrome | Native OS titlebar + in-app topbar (not frameless) |
| Delivery | Shell system first, then page-by-page polish |
| Approach | Token-driven progressive theming |
| Theme | Dark only (no light mode this phase) |

## Visual language

### Color (CC Switch–inspired)

| Role | Token | Value |
|------|-------|-------|
| Window bg | `--rf-bg-base` | `#121212` |
| Shell | `--rf-bg-shell` | `#171717` |
| Panel | `--rf-bg-panel` | `#1e1e1e` |
| Active / nav | `--rf-accent` | `#2dd4bf` (teal) |
| Primary CTA | `--rf-cta` | `#f97316` (orange) |

### Shell

Top bar (no left sidebar): brand + pill nav | proxy status + project select + orange `+` CTA.

### Settings

Pill tabs (AI / 代理 / 用量 / 提示词) + large section titles + card rows like CC Switch.

### Typography

- UI: `"Segoe UI Variable", "PingFang SC", "Microsoft YaHei", sans-serif`
- Mono: `"Cascadia Code", "JetBrains Mono", Consolas, monospace` (system fonts, not bundled)

### Scale

- Radius: shell `8px`, controls `6px`, tags `4px`
- Spacing: `4 / 8 / 12 / 16 / 24`
- Sidebar: `220px`; Topbar: `44px`

### Principles

- No emoji-as-icons; use Element Plus Icons or SVG
- Restrained cards; hierarchy via background layers and borders
- Motion: `150–220ms` ease — nav, hover, status only

## App shell

```
[ Native OS titlebar ]
[ AppSidebar 220px | AppTopbar 44px ]
[                  | router-view     ]
```

- **Sidebar:** wordmark (no shield emoji) + custom nav + ProjectPicker footer
- **Topbar:** page title | proxy status pill (navigate to traffic) | current project
- **Consent:** keep blocking logic; restyle to tokens

## Interaction

- Route fade ~180ms on main content
- Active nav: copper left rail + raised background
- EmptyState for guidance; keep warning alerts where critical
- Proxy start/stop stays on Traffic toolbar; topbar is display + link

## Page polish order

1. Traffic → 2. Task tree → 3. Repeater → 4. Findings → 5. Settings

## Out of scope

Light theme, frameless window, UI library swap, Monaco, full `Rf*` wrapper kit, i18n.
