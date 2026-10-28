import { defineConfig } from "@playwright/test";
export default defineConfig({testDir: "./e2e", timeout: 30_000, workers: 1,
  use: {browserName: "chromium", headless: true, viewport: {width: 1360, height: 1000}},
  reporter: "list"});
