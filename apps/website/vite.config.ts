import react from "@vitejs/plugin-react";
import { defineConfig } from "vite-plus";
import type { PluginOption } from "vite-plus";

export default defineConfig({
  plugins: [...react()] as PluginOption[],
});
