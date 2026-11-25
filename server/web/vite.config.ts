import { defineConfig } from "vite";

export default defineConfig({
  server: { fs: { allow: [".", "../../proto"] } },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
