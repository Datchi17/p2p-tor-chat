import { defineConfig } from 'vite'
import solid from 'vite-plugin-solid'

export default defineConfig({
  plugins: [solid()],
  clearScreen: false,
  server: { port: 1420, strictPort: true, host: '127.0.0.1' },
  build: {
    target: ['es2022', 'chrome110', 'safari16'],
    sourcemap: false,
    // No inline scripts/styles: keeps the strict CSP working.
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
  },
})
