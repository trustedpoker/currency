/// <reference types="vite/client" />
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { config } from 'dotenv';
import { resolve } from 'node:path';
import { fileURLToPath, URL } from 'node:url';
import { defineConfig } from 'vite';
import dts from 'vite-plugin-dts';
import { nodePolyfills } from 'vite-plugin-node-polyfills';
import tsconfigPaths from 'vite-tsconfig-paths';

import { peerDependencies, devDependencies } from './package.json';

config({ path: "../../.env" });

/** @type {import('vite').UserConfig} */
export default defineConfig(({ mode }) => ({
  build: {
    emptyOutDir: true,
    copyPublicDir: false,
    target: "esnext",
    lib: {
      entry: resolve(__dirname, "ui/index.ts"),
      formats: ["es"],
    },
    rollupOptions: {
      external: [
        '@zk-game-dao/ui',
        "react",
        "react-dom",
        "react/jsx-runtime",
        "framer-motion",
        "buffer",
        ...Object.keys(peerDependencies),
        ...Object.keys(devDependencies),
      ],
      output: {
        assetFileNames: "assets/[name][extname]",
        entryFileNames: "[name].js",

        globals: {
          react: "React",
          "react-dom": "React-dom",
          "react/jsx-runtime": "react/jsx-runtime",
        },
      },
    },
  },


  optimizeDeps: {
    // exclude: ["react-helmet", "react-json-view-lite"],
    // esbuildOptions: {
    //   plugins: [
    //     NodeGlobalsPolyfillPlugin({
    //       buffer: true,
    //       process: true,
    //     }),
    //   ],
    // },
    exclude: [
      "@storybook/builder-vite",
      // "vite-plugin-node-polyfills/shims/buffer",
      // "vite-plugin-node-polyfills/shims/global",
      // "vite-plugin-node-polyfills/shims/process",
      "chromatic",
      "buffer",
    ],
  },
  server: {
    proxy: {
      "/api": {
        target: "http://127.0.0.1:4943",
        changeOrigin: true,
      },
    },
  },
  plugins: [
    tailwindcss(),
    react(),
    tsconfigPaths(),
    mode === "development" && nodePolyfills(),
    dts({ rollupTypes: true })
  ].filter(Boolean),
  resolve: {
    alias: [
      {
        find: "crypto",
        replacement: "empty-module",
      },
      {
        find: "declarations",
        replacement: fileURLToPath(
          new URL("../declarations", import.meta?.url)
        ),
      },
    ],
  },
  define: {
    'process.env': 'import.meta.env',
  },
}));
