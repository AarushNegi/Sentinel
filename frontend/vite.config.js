import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Vitest 3 still transforms JSX through esbuild; use the automatic runtime
  // so test files and components don't need an explicit React import.
  esbuild: { jsx: 'automatic' },
  test: {
    environment: 'jsdom',
    setupFiles: './src/setupTests.js',
    css: false,
  },
})
