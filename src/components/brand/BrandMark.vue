<script setup lang="ts">
withDefaults(
  defineProps<{
    /** Pixel size for width and height */
    size?: number;
    /** mono: UI chrome mark; app: full-color packaging mark */
    variant?: "mono" | "app";
  }>(),
  { size: 20, variant: "mono" }
);
</script>

<template>
  <svg
    class="rf-brand-mark"
    :class="[`is-${variant}`]"
    :width="size"
    :height="size"
    viewBox="0 0 1024 1024"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
    aria-hidden="true"
    focusable="false"
  >
    <defs>
      <!-- Core Radiant Flame Gradient (Amber/Gold) -->
      <linearGradient id="bm-core-grad" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#fbbf24" />
        <stop offset="50%" stop-color="#f97316" />
        <stop offset="100%" stop-color="#ea580c" />
      </linearGradient>
    </defs>

    <template v-if="variant === 'app'">
      <!-- Theme Adaptive Rounded Container -->
      <rect
        class="bm-bg-rect"
        x="32"
        y="32"
        width="960"
        height="960"
        rx="224"
      />

      <g transform="translate(0, 10)">
        <!-- Top Anvil Head Facet -->
        <path class="bm-facet-top" d="M512 216 L768 364 L512 512 L256 364 Z" />
        <!-- Top Facet Inner Cut -->
        <path class="bm-facet-cut" d="M512 286 L660 372 L512 458 L364 372 Z" />
        <!-- Left Pillar -->
        <path class="bm-facet-left" d="M256 398 L488 532 L488 776 L256 642 Z" />
        <!-- Right Pillar -->
        <path class="bm-facet-right" d="M536 532 L768 398 L768 642 L536 776 Z" />
        <!-- Central Forge Core -->
        <path d="M512 376 L604 492 L512 608 L420 492 Z" fill="url(#bm-core-grad)" />
      </g>
    </template>

    <template v-else>
      <g fill="currentColor" transform="translate(0, 10)">
        <path d="M512 216 L768 364 L512 512 L256 364 Z" />
        <path d="M256 398 L488 532 L488 776 L256 642 Z" opacity="0.75" />
        <path d="M536 532 L768 398 L768 642 L536 776 Z" opacity="0.85" />
        <path d="M512 376 L604 492 L512 608 L420 492 Z" fill="var(--rf-accent)" />
      </g>
    </template>
  </svg>
</template>

<style scoped>
.rf-brand-mark {
  display: block;
  flex-shrink: 0;
}

/* Light Theme: Clean Slate & Titanium Container */
.bm-bg-rect {
  fill: #f1f5f9;
  stroke: #cbd5e1;
  stroke-width: 20px;
  transition: fill var(--rf-duration) var(--rf-ease), stroke var(--rf-duration) var(--rf-ease);
}

.bm-facet-top {
  fill: #1e293b;
  transition: fill var(--rf-duration) var(--rf-ease);
}

.bm-facet-cut {
  fill: #f1f5f9;
  opacity: 0.95;
  transition: fill var(--rf-duration) var(--rf-ease);
}

.bm-facet-left {
  fill: #475569;
  transition: fill var(--rf-duration) var(--rf-ease);
}

.bm-facet-right {
  fill: #334155;
  transition: fill var(--rf-duration) var(--rf-ease);
}

/* Dark Theme: Deep Titanium & Crisp Steel */
:global(html.dark) .bm-bg-rect {
  fill: #18181c;
  stroke: rgba(255, 255, 255, 0.14);
}

:global(html.dark) .bm-facet-top {
  fill: #f4f4f5;
}

:global(html.dark) .bm-facet-cut {
  fill: #18181c;
}

:global(html.dark) .bm-facet-left {
  fill: #52525b;
}

:global(html.dark) .bm-facet-right {
  fill: #71717a;
}
</style>
