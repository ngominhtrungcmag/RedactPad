import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'
import tauriConfig from './src-tauri/tauri.conf.json' with { type: 'json' }

export default defineConfig({
  plugins: [react()],
  base: './',
  server: {
    host: '127.0.0.1',
    port: 1420,
    strictPort: true,
    hmr: false,
    headers: { 'Content-Security-Policy': tauriConfig.app.security.devCsp },
  },
})
