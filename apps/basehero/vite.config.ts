import { defineConfig } from 'vitest/config';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { assertPatchedYjs } from './scripts/patch-yjs.mjs';

assertPatchedYjs();

export default defineConfig({
  plugins: [svelte()],
  resolve: { dedupe: ['yjs'], alias: [{ find: /^svelte$/, replacement: new URL('./node_modules/svelte/src/index-client.js', import.meta.url).pathname }] },
  test: { environment: 'jsdom', include: ['src/**/*.test.ts'] },
});
