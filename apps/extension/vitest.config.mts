import { defineConfig } from "vitest/config";

export default defineConfig({
  test: { environment: "jsdom", globals: true, setupFiles: ["./test/chrome-fake.ts"], include: ["test/**/*.test.ts"] },
});
