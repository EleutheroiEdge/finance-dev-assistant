import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()], base: "./",
  build: { outDir: "../src/finassist/resources/dashboard", emptyOutDir: true, sourcemap: false },
  test: { environment: "jsdom", setupFiles: ["./src/test-setup.ts"], include: ["src/**/*.test.tsx"] },
});
