import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Im Entwicklungsmodus leitet Vite /api an den lokal laufenden pc-server weiter.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': path.resolve(import.meta.dirname, './src') },
  },
  server: {
    proxy: { '/api': process.env.PC_API ?? 'http://localhost:8080' },
  },
  build: {
    chunkSizeWarningLimit: 1500,
  },
})
