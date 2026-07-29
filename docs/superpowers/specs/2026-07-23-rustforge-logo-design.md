# RustForge Logo Design — Evidence Strike

**Date:** 2026-07-29

**Status:** Approved and implemented

**Concept:** 证据锻击（Evidence Strike）

## Product fit

RustForge is an evidence-driven, human-in-the-loop security testing workbench for authorized targets. The mark should feel professional, precise, technical, and deliberately controlled rather than aggressive or autonomous.

The final mark combines four product ideas:

1. A bold F-shaped anvil represents hypotheses being shaped into testable findings.
2. A floating inner crossbar keeps the F legible without weakening the anvil silhouette.
3. A detached teal verification ribbon represents accepted evidence and human review.
4. A detached, solid-core ten-ray forge rosette represents guided analysis and the moment of decision.

## Geometry

Master viewBox: `0 0 1024 1024`

- **Background:** `1024 × 1024` squircle, corner radius `216`
- **F-shaped anvil:**

  ```text
  M751.3 311.1 134.7 349.5 303.8 463 245 601
  328.3 709.6 453.2 458.1 660.6 423Z
  ```

- **Floating crossbar:**

  ```text
  M616.5 498.9 477.7 521 427.9 619.8 564.3 592Z
  ```

- **Verification ribbon:**

  ```text
  M490.8 654.1 402.6 670.4 359.3 757.8 332.4 764.3
  231.9 631.2 110.2 902.3 400.1 848.4Z
  ```

- **Forge rosette:** ten asymmetric rays joined through one solid orange center
- **Spark spacing:** the rosette remains visibly detached from the anvil horn
- **Safe area:** all colored geometry remains inside the desktop icon squircle
- **Construction:** native vector paths with flat fills and no strokes

## Color

| Role | Hex | Usage |
|------|-----|-------|
| Midnight | `#050B20` | App-icon squircle |
| Signal blue | `#2070F8` | F-shaped anvil and crossbar |
| Verification teal | `#19BCB9` | Detached evidence ribbon |
| Forge orange | `#FC8442` | Solid-core ten-ray rosette |

The implementation uses sampled flat fills instead of the generated concept's faint raster texture so that small desktop and mobile icons remain sharp.

## Variants

| Variant | File / component | Use |
|---------|------------------|-----|
| App icon SVG | `src/assets/brand/rustforge-app-icon.svg` | Packaging source of truth |
| App icon PNG | `src/assets/brand/rustforge-app-icon-1024.png` | 1024 px raster master |
| Lockup | `src/assets/brand/rustforge-lockup.svg` | Docs and marketing |
| UI mark | `src/components/brand/BrandMark.vue` | Full-color and monochrome app UI |
| Favicon | `public/favicon.svg` | WebView and browser tab |
| Platform icons | `src-tauri/icons/` | Windows, macOS, Linux, Android, and iOS |

## Size rules

| Size | Rule |
|------|------|
| 16 px | The F/anvil silhouette remains primary; the rosette may resolve as one orange accent |
| 20–28 px UI | Prefer the monochrome `BrandMark` without the background square |
| 32–128 px | Use the full-color icon and preserve all four color regions |
| ≥256 px | Use the exact SVG geometry |

## Don'ts

- Do not join the rosette to the anvil horn.
- Do not cut a hole into the rosette center.
- Do not copy another product's exact ray count, proportions, angles, or silhouette.
- Do not replace the anvil with a lock, shield, skull, bug, robot, weapon, or typed letter.
- Do not add text, thin strokes, bevels, glow, shadows, or raster texture.
- Do not recolor the application shell tokens as part of an icon-only change.

## Regeneration

Regenerate the complete Tauri icon set from the SVG source:

```powershell
pnpm tauri icon src/assets/brand/rustforge-app-icon.svg --ios-color "#050B20"
```

The checked-in icon set includes Windows AppX tiles and ICO, macOS ICNS, Linux PNGs, Android launcher assets, and iOS app icons.
