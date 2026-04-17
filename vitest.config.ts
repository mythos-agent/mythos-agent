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
      // Starting thresholds reflect today's ~22% coverage. Raise these as
      // test coverage grows. Consider aiming for 60/60/55/60 once the scanner
      // test matrix is fleshed out.
      thresholds: {
        lines: 20,
        functions: 30,
        branches: 55,
        statements: 20,
      },
    },
  },
});
