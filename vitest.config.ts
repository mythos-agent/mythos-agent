import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/**/__tests__/**/*.test.ts"],
    testTimeout: 10000,
    coverage: {
      provider: "v8",
      reporter: ["text", "html", "lcov"],
      include: ["src/**/*.ts"],
      exclude: [
        "src/**/__tests__/**",
        "src/**/*.d.ts",
        "src/types/**",
        "dist/**",
      ],
      // Thresholds are set slightly below current coverage so CI doesn't
      // break from noise. Raise them as the scanner test matrix grows.
      // Current baseline: lines 37% / branches 62% / functions 56%.
      thresholds: {
        lines: 35,
        functions: 50,
        branches: 60,
        statements: 35,
      },
    },
  },
});
