// `defineConfig` lives in `vitest/config`, not `vitest`, in Vitest 4. Importing it from the bare
// package made `tsc --noEmit`, `vitest run` and `next build` all fail — the config file could not
// even be loaded, so the test step crashed before running a single test.
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
  },
});
