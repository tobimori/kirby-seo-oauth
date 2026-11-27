import { defineConfig } from "vite-plus";

const ignorePatterns = [".repos/**", ".wrangler/**", "node_modules/**"];

export default defineConfig({
  fmt: {
    ignorePatterns,
    printWidth: 100,
    sortPackageJson: true,
  },
  lint: {
    ignorePatterns,
    options: {
      typeAware: true,
      typeCheck: true,
    },
  },
});
