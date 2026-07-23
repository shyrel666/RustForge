<script setup lang="ts">
import { computed, useId } from "vue";

const props = withDefaults(
  defineProps<{
    /** Pixel size for width and height */
    size?: number;
    /** mono: UI chrome stroke; app: full-color packaging mark */
    variant?: "mono" | "app";
  }>(),
  { size: 20, variant: "mono" }
);

const uid = useId().replace(/[^a-zA-Z0-9_-]/g, "");
const gradId = computed(() => `rf-path-${uid}`);
</script>

<template>
  <svg
    class="rf-brand-mark"
    :class="[`is-${variant}`]"
    :width="size"
    :height="size"
    :viewBox="variant === 'app' ? '0 0 512 512' : '0 0 24 24'"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
    aria-hidden="true"
    focusable="false"
  >
    <template v-if="variant === 'app'">
      <defs>
        <linearGradient
          :id="gradId"
          x1="96"
          y1="400"
          x2="400"
          y2="112"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0%" stop-color="#5B8CFF" />
          <stop offset="100%" stop-color="#35E0C1" />
        </linearGradient>
      </defs>
      <rect width="512" height="512" rx="108" fill="#0B1020" />
      <path
        d="M 118 388 L 176 260 H 286 L 360 136"
        fill="none"
        :stroke="`url(#${gradId})`"
        stroke-width="46"
        stroke-linecap="round"
        stroke-linejoin="round"
      />
      <path
        d="M 386 78 L 402.5 110.5 L 435 127 L 402.5 143.5 L 386 176 L 369.5 143.5 L 337 127 L 369.5 110.5 Z"
        fill="#FF7A45"
      />
    </template>
    <template v-else>
      <!-- Guided path implying F: rise → mid bar → rise -->
      <path
        d="M 5.5 18.2 L 8.2 12.2 H 13.4 L 16.9 6.4"
        stroke="currentColor"
        stroke-width="2.2"
        stroke-linecap="round"
        stroke-linejoin="round"
      />
      <path
        d="M 18.15 2.95 L 19.2 4.9 L 21.15 5.95 L 19.2 7 L 18.15 8.95 L 17.1 7 L 15.15 5.95 L 17.1 4.9 Z"
        fill="currentColor"
      />
    </template>
  </svg>
</template>

<style scoped>
.rf-brand-mark {
  display: block;
  flex-shrink: 0;
}
.rf-brand-mark.is-app {
  border-radius: 22%;
}
</style>
