import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

type ProxyRequestHook = {
  on: (event: 'proxyReq', listener: (request: { setHeader: (name: string, value: string) => void }) => void) => void;
};

export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    strictPort: true,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8765',
        changeOrigin: true,
        configure(proxy) {
          (proxy as unknown as ProxyRequestHook).on('proxyReq', (proxyRequest) => {
            proxyRequest.setHeader('Origin', 'http://127.0.0.1:8765');
          });
        },
      },
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test-setup.ts'],
    clearMocks: true,
    include: ['src/**/*.test.{ts,tsx}'],
    testTimeout: 30_000,
  },
});
