import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    proxy: {
      // Auth endpoints -> IAM Server (port 4000)
      '/api/login': {
        target: 'http://api-gateway:8080',
        changeOrigin: true,
        secure: false
      },
      '/api/mfa': {
        target: 'http://api-gateway:8080',
        changeOrigin: true,
        secure: false
      },
      '/api/token': {
        target: 'http://api-gateway:8080',
        changeOrigin: true,
        secure: false
      },
      '/api/logout': {
        target: 'http://api-gateway:8080',
        changeOrigin: true,
        secure: false
      },
      '/api/me': {
        target: 'http://api-gateway:8080',
        changeOrigin: true,
        secure: false
      },
      '/api/admin': {
        target: 'http://api-gateway:8080',
        changeOrigin: true,
        secure: false
      },
      // Data endpoints -> Backend Server (port 3000)
      '/api/patients': {
        target: 'http://api-gateway:8080',
        changeOrigin: true,
        secure: false
      },
      '/api/appointments': {
        target: 'http://api-gateway:8080',
        changeOrigin: true,
        secure: false
      },
      '/api/vitals': {
        target: 'http://api-gateway:8080',
        changeOrigin: true,
        secure: false
      },
      '/api/prescriptions': {
        target: 'http://api-gateway:8080',
        changeOrigin: true,
        secure: false
      },
      '/api/lab': {
        target: 'http://api-gateway:8080',
        changeOrigin: true,
        secure: false
      },
      '/api/billing': {
        target: 'http://api-gateway:8080',
        changeOrigin: true,
        secure: false
      },
      '/api/pharmacy': {
        target: 'http://api-gateway:8080',
        changeOrigin: true,
        secure: false
      },
      '/api/files': {
        target: 'http://api-gateway:8080',
        changeOrigin: true,
        secure: false
      },
      '/api/audit': {
        target: 'http://api-gateway:8080',
        changeOrigin: true,
        secure: false
      },
      '/api/monitoring': {
        target: 'http://api-gateway:8080',
        changeOrigin: true,
        secure: false
      },
      '/api/health': {
        target: 'http://api-gateway:8080',
        changeOrigin: true,
        secure: false
      },
      '/api/dashboard': {
        target: 'http://api-gateway:8080',
        changeOrigin: true,
        secure: false
      },
      // Default fallback -> IAM Server
      '/api': {
        target: 'http://api-gateway:8080',
        changeOrigin: true,
        secure: false
      }
    }
  }
})
