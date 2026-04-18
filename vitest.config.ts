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
      // Thresholds are floors, not aspirations. Set slightly below current
      // coverage so CI doesn't break from noise; raise them as new test
      // surfaces (scanners / CLI commands / agent harness) come online.
      // Tracked under the H1 2026 "80% CLI test coverage" bucket.
      // Current baseline (post CLI smoke tests): lines ~37% / branches ~60% /
      // functions ~56%. Smoke tests added new import-tracked files which
      // surfaced previously-invisible branches; the branches threshold was
      // dropped from 60 to 55 to absorb that and will tighten as more
      // commands gain real tests.
      thresholds: {
        lines: 35,
        functions: 50,
        branches: 55,
        statements: 35,
      },
    },
  },
});
