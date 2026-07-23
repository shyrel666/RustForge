# RustForge Logo Design — Guided Spark

**Date:** 2026-07-23  
**Status:** Approved for implementation  
**Concept:** 引导火花（Guided Spark）

## Product fit

RustForge is an AI-guided penetration-learning desktop app for authorized beginners. The mark should feel **professional, trustworthy, and gently sharp** — not aggressive hacking cliché.

Core product loop encoded in the mark:

1. Capture (path origin)  
2. Analyze / guide (mid bar + ascending turn)  
3. Verify / grow (terminal spark)

## Concept

A three-segment ascending path that implies the letter **F** (Forge), ending in a four-pointed spark. No shields, locks, skulls, hammers, or anvils.

| Segment | Geometry role | Product meaning |
|---------|---------------|-----------------|
| 1 | Rise from lower-left | Traffic capture |
| 2 | Horizontal mid bar | AI analysis / task fork |
| 3 | Rise to upper-right | Guided progress |
| Spark | Four-point star at tip | Human verification & skill forged |

## Geometry (24×24 mark grid)

ViewBox: `0 0 24 24`

- **Path:** `M 5.5 18.2 L 8.2 12.2 H 13.4 L 16.9 6.4`
- **Stroke:** round caps/joins; UI mark stroke-width `2.2`; app-icon stroke scaled proportionally (~46 on 512 canvas)
- **Spark center:** `(18.15, 5.05)`
- **Spark:** four-point diamond star, tip-to-tip ≈ `4.2` on 24-grid (readable at 16px)
- **Safe padding:** ≥ 12% of canvas edge for app icon; mark sits optically centered

## Color

### Full-color app icon

| Role | Hex | Usage |
|------|-----|-------|
| Ink blue | `#0B1020` | Rounded-square background |
| Signal blue | `#5B8CFF` | Path gradient start |
| Bright cyan | `#35E0C1` | Path gradient end |
| Spark orange | `#FF7A45` | Terminal spark fill |

Path uses a linear gradient along the ascent (`#5B8CFF` → `#35E0C1`).

### UI monochrome mark

- Stroke/fill: `currentColor` (inherits Topbar / About accent)
- No background square in chrome
- Does **not** change existing UI tokens (`--rf-accent`, `--rf-cta`)

### Wordmark

- Text: `RustForge` (no space)
- Family: Segoe UI Variable / Segoe UI / PingFang SC stack
- Weight: 700; letter-spacing ≈ `-0.02em`
- Lockup: mark left, wordmark right, optical gap ≈ mark width × 0.35

## Variants

| Variant | File / component | Use |
|---------|------------------|-----|
| App icon (color) | `src/assets/brand/rustforge-app-icon.svg` | Windows / Tauri packaging source |
| Lockup | `src/assets/brand/rustforge-lockup.svg` | Docs, README, marketing |
| UI mark | `src/components/brand/BrandMark.vue` | Topbar 20px, About 28px |
| Favicon | `public/favicon.svg` | WebView / browser tab |

## Size rules

| Size | Rules |
|------|-------|
| 16px | Keep path + spark; no gradient needed in raster if aliased — prefer solid mid cyan for tiny PNG if needed |
| 20–28px UI | Monochrome `BrandMark`; spark must remain a distinct diamond, not a blob |
| 32–128px | Full color OK; maintain stroke weight optical balance |
| ≥256px | Full gradient + crisp spark |

**Minimum:** do not ship a mark smaller than 16px without increasing spark scale.

## Don'ts

- Do not use emoji as the brand mark
- Do not replace the spark with a lock/shield
- Do not recolor the UI shell tokens to match logo blues without a separate design change
- Do not squash the path into a closed hexagon (legacy placeholder)

## Integration targets

- Topbar brand: `AppTopbar.vue` → `BrandMark` size 20
- About card: `SettingsView.vue` → `BrandMark` size 28
- Desktop icons: `pnpm tauri icon src/assets/brand/rustforge-app-icon.svg`
- Favicon: `index.html` → `/favicon.svg`
