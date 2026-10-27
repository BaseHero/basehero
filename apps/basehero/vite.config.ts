import { defineConfig } from 'vitest/config';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { assertPatchedYjs } from './scripts/patch-yjs.mjs';

assertPatchedYjs();

export default defineConfig({
  plugins: [svelte()],
  resolve: { dedupe: ['yjs'] },
  test: { environment: 'jsdom', include: ['src/**/*.test.ts'] },
});
